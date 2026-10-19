"""Deploy v1.3; preserve the existing CloudFront domain and save local recovery state.

Run from backend: uv run python infra/deploy_serverless.py
This command does not terminate EC2. Retire it only after live verification.
"""

import json
import mimetypes
import sys
import time
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import Settings
from infra.admin_origin import configure_admin_origin
from infra.cors import configure_gateway_responses, extension_origin, update_lambda_origins
from infra.create_tables import create_tables
from store import Store

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deploy" / "aws"
CONFIG = json.loads((OUT / "resources.json").read_text())
OLD = json.loads((OUT / "deployment.json").read_text())
STATE_PATH = OUT / "serverless.json"
STATE = json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else {}
REGION = CONFIG["region"]
SESSION = boto3.Session(profile_name=CONFIG["profile"], region_name=REGION)
RETRIES = Config(retries={"mode": "adaptive", "max_attempts": 10})
TAGS = {"Project": "securedrop", "ManagedBy": "securedrop-deploy"}


def save(**values):
    STATE.update(values)
    STATE_PATH.write_text(json.dumps(STATE, indent=2) + "\n", encoding="utf-8")


def log(message):
    print(message, flush=True)


def role(iam, name, service, policy):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
        ],
    }
    try:
        result = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
        )["Role"]
    except iam.exceptions.EntityAlreadyExistsException:
        result = iam.get_role(RoleName=name)["Role"]
    iam.put_role_policy(
        RoleName=name, PolicyName="securedrop-runtime", PolicyDocument=json.dumps(policy)
    )
    return result["Arn"]


def main():
    account = SESSION.client("sts").get_caller_identity()["Account"]
    if account != CONFIG["account_id"]:
        raise RuntimeError("AWS account mismatch")
    s3, iam, lam, api, cf = [
        SESSION.client(name, config=RETRIES)
        for name in ("s3", "iam", "lambda", "apigateway", "cloudfront")
    ]
    files = f"securedrop-files-{account}-{REGION}"
    web = f"securedrop-web-{account}-{REGION}"
    base = OLD["url"]
    distribution = OLD["distribution_id"]
    cf_base = OLD["cloudfront_url"]
    origins = [
        base,
        cf_base,
        "http://localhost:5500",
        "http://localhost:8000",
        "http://127.0.0.1:5500",
    ]
    if "--frontend-only" in sys.argv:
        deploy_frontend(s3, cf, account, files, web, distribution, STATE["api_base"])
        return
    origins = list(
        dict.fromkeys(
            [
                *origins,
                *Settings().allowed_origins,
                extension_origin(ROOT.parent / "extension" / "manifest.json"),
            ]
        )
    )
    if "--cors-only" in sys.argv:
        applied = update_lambda_origins(lam, "securedrop-api", origins)
        configure_gateway_responses(api, STATE["api_id"])
        api.create_deployment(
            restApiId=STATE["api_id"], stageName="prod", description="SecureDrop CORS update"
        )
        log("CORS updated: " + ",".join(applied))
        return
    save(
        region=REGION,
        files_bucket=files,
        web_bucket=web,
        url=base,
        distribution_id=distribution,
        old_instance_id=OLD["instance_id"],
    )
    for bucket in (files, web):
        try:
            s3.head_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
                raise
            s3.create_bucket(
                Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION}
            )
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in TAGS.items()]}
        )
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                k: True
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            },
        )
        s3.put_bucket_ownership_controls(
            Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        )
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
    s3.put_bucket_lifecycle_configuration(
        Bucket=files,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "expire-transfers",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "transfers/"},
                    "Expiration": {"Days": 1},
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                }
            ]
        },
    )
    s3.put_bucket_cors(
        Bucket=files,
        CORSConfiguration={
            "CORSRules": [
                {
                    "AllowedOrigins": origins,
                    "AllowedMethods": ["GET", "POST"],
                    "AllowedHeaders": ["*"],
                    "ExposeHeaders": ["ETag"],
                    "MaxAgeSeconds": 3000,
                }
            ]
        },
    )
    s3.put_bucket_policy(
        Bucket=files,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{files}", f"arn:aws:s3:::{files}/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )
    log("Private S3 buckets ready")
    create_tables(Store(Settings(aws_profile=CONFIG["profile"])))
    log("DynamoDB tables ready")
    function = "securedrop-api"
    function_arn = f"arn:aws:lambda:{REGION}:{account}:function:{function}"
    tables = [
        f"arn:aws:dynamodb:{REGION}:{account}:table/sd_{name}"
        for name in ("admins", "admin_sessions", "sessions", "transfers", "events")
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
                "Resource": f"arn:aws:s3:::{files}/transfers/*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                ],
                "Resource": tables + [tables[3] + "/index/day-created-index"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{function}:*",
            },
        ],
    }
    arn = role(iam, "securedrop-lambda-v13", "lambda.amazonaws.com", policy)
    logs = SESSION.client("logs")
    for group in (f"/aws/lambda/{function}", "/apigw/securedrop-api"):
        try:
            logs.create_log_group(logGroupName=group, tags=TAGS)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        logs.put_retention_policy(logGroupName=group, retentionInDays=14)
    environment = {
        "APP_ENV": "prod",
        "FILES_BUCKET": files,
        "PUBLIC_BASE_URL": base,
        "ALLOWED_ORIGINS": ",".join(origins),
    }
    package = (ROOT / "dist" / "securedrop-api.zip").read_bytes()
    try:
        lam.get_function(FunctionName=function)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(12):
            try:
                lam.create_function(
                    FunctionName=function,
                    Runtime="python3.12",
                    Role=arn,
                    Handler="handler.handler",
                    Code={"ZipFile": package},
                    Timeout=25,
                    MemorySize=1024,
                    Architectures=["x86_64"],
                    Environment={"Variables": environment},
                    Tags=TAGS,
                )
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 11:
                    raise
                time.sleep(5)
    else:
        lam.update_function_code(FunctionName=function, ZipFile=package)
        lam.get_waiter("function_updated_v2").wait(FunctionName=function)
        lam.update_function_configuration(
            FunctionName=function,
            Runtime="python3.12",
            Role=arn,
            Handler="handler.handler",
            Timeout=25,
            MemorySize=1024,
            Environment={"Variables": environment},
        )
    lam.get_waiter("function_active_v2").wait(FunctionName=function)
    lam.get_waiter("function_updated_v2").wait(FunctionName=function)
    lam.put_function_concurrency(FunctionName=function, ReservedConcurrentExecutions=10)
    log("Lambda ready")
    if "api_id" not in STATE:
        existing = [item for item in api.get_rest_apis()["items"] if item["name"] == function]
        rest = (
            existing[0]
            if existing
            else api.create_rest_api(
                name=function,
                endpointConfiguration={"types": ["REGIONAL"]},
                binaryMediaTypes=["multipart/form-data"],
                tags=TAGS,
            )
        )
        save(api_id=rest["id"])
    api_id = STATE["api_id"]
    api_base = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/prod"
    save(api_base=api_base)
    resource_map = {
        r["path"]: r["id"] for r in api.get_resources(restApiId=api_id, limit=500)["items"]
    }

    def resource(path):
        if path not in resource_map:
            parent, name = path.rsplit("/", 1)
            resource_map[path] = api.create_resource(
                restApiId=api_id, parentId=resource(parent or "/"), pathPart=name
            )["id"]
        return resource_map[path]

    paths = [
        "/api/{proxy+}",
        "/docs",
        "/openapi.json",
        "/api/health",
        "/api/scan",
        "/api/d/{id}",
        "/api/ext/logs",
        "/api/admin/login",
        "/api/plugin/{proxy+}",
        "/api/plugin/openapi.json",
    ]
    for path in paths:
        rid = resource(path)
        method_name = (
            "GET"
            if path
            in ("/docs", "/openapi.json", "/api/health", "/api/d/{id}", "/api/plugin/openapi.json")
            else "POST"
            if path in ("/api/scan", "/api/ext/logs", "/api/admin/login")
            else "ANY"
        )
        for method in (method_name, "OPTIONS"):
            try:
                api.put_method(
                    restApiId=api_id,
                    resourceId=rid,
                    httpMethod=method,
                    authorizationType="NONE",
                    apiKeyRequired=path == "/api/plugin/{proxy+}" and method != "OPTIONS",
                )
            except api.exceptions.ConflictException:
                api.update_method(
                    restApiId=api_id,
                    resourceId=rid,
                    httpMethod=method,
                    patchOperations=[
                        {
                            "op": "replace",
                            "path": "/apiKeyRequired",
                            "value": str(
                                path == "/api/plugin/{proxy+}" and method != "OPTIONS"
                            ).lower(),
                        }
                    ],
                )
            api.put_integration(
                restApiId=api_id,
                resourceId=rid,
                httpMethod=method,
                type="AWS_PROXY",
                integrationHttpMethod="POST",
                uri=f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function_arn}/invocations",
                timeoutInMillis=29000,
            )
    try:
        lam.add_permission(
            FunctionName=function,
            StatementId="securedrop-gateway",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=f"arn:aws:execute-api:{REGION}:{account}:{api_id}/*/*/*",
        )
    except lam.exceptions.ResourceConflictException:
        pass
    log_role = role(
        iam,
        "securedrop-apigateway-logs",
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                        "logs:GetLogEvents",
                        "logs:FilterLogEvents",
                    ],
                    "Resource": "*",
                }
            ],
        },
    )
    if not api.get_account().get("cloudwatchRoleArn"):
        for attempt in range(12):
            try:
                api.update_account(
                    patchOperations=[
                        {"op": "replace", "path": "/cloudwatchRoleArn", "value": log_role}
                    ]
                )
                break
            except (api.exceptions.BadRequestException, api.exceptions.TooManyRequestsException):
                if attempt == 11:
                    raise
                time.sleep(30)
    configure_gateway_responses(api, api_id)
    api.create_deployment(restApiId=api_id, stageName="prod", description="SecureDrop v1.3")
    patches = [
        {"op": "replace", "path": path, "value": value}
        for path, value in [
            ("/*/*/throttling/rateLimit", "20"),
            ("/*/*/throttling/burstLimit", "40"),
            ("/*/*/logging/dataTrace", "false"),
            ("/*/*/logging/loglevel", "INFO"),
            ("/*/*/metrics/enabled", "true"),
            (
                "/accessLogSettings/destinationArn",
                f"arn:aws:logs:{REGION}:{account}:log-group:/apigw/securedrop-api",
            ),
            (
                "/accessLogSettings/format",
                '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath","status":"$context.status","responseLatency":"$context.responseLatency"}',
            ),
        ]
    ]
    for path in ("/api/health", "/api/scan", "/api/d/{id}", "/api/ext/logs", "/api/admin/login"):
        encoded = path.replace("/", "~1")
        method_name = "GET" if path in ("/api/health", "/api/d/{id}") else "POST"
        for name, value in [
            ("rateLimit", "1" if path.endswith("login") else "5"),
            ("burstLimit", "5" if path.endswith("login") else "10"),
        ]:
            patches.append(
                {
                    "op": "replace",
                    "path": f"/{encoded}/{method_name}/throttling/{name}",
                    "value": value,
                }
            )
    api.update_stage(restApiId=api_id, stageName="prod", patchOperations=patches)
    if "usage_plan_id" not in STATE:
        plan = api.create_usage_plan(
            name="securedrop-plugin-plan",
            apiStages=[{"apiId": api_id, "stage": "prod"}],
            throttle={"rateLimit": 0.5, "burstLimit": 5},
            quota={"limit": 2000, "period": "DAY"},
            tags=TAGS,
        )
        save(usage_plan_id=plan["id"])
    if "plugin_key_id" not in STATE:
        key = api.create_api_key(name="securedrop-demo-v13", enabled=True, tags=TAGS)
        save(plugin_key_id=key["id"])
        api.create_usage_plan_key(
            usagePlanId=STATE["usage_plan_id"], keyId=key["id"], keyType="API_KEY"
        )
    log("API Gateway ready: " + api_base)
    deploy_frontend(s3, cf, account, files, web, distribution, api_base)


def deploy_frontend(s3, cf, account, files, web, distribution, api_base):
    if "oac_id" not in STATE:
        oac = cf.create_origin_access_control(
            OriginAccessControlConfig={
                "Name": "securedrop-web-v13",
                "Description": "Private demo frontend",
                "SigningProtocol": "sigv4",
                "SigningBehavior": "always",
                "OriginAccessControlOriginType": "s3",
            }
        )
        save(oac_id=oac["OriginAccessControl"]["Id"])
    s3.put_bucket_policy(
        Bucket=web,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudfront.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{web}/*",
                        "Condition": {
                            "StringEquals": {
                                "AWS:SourceArn": f"arn:aws:cloudfront::{account}:distribution/{distribution}"
                            }
                        },
                    },
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{web}", f"arn:aws:s3:::{web}/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                ],
            }
        ),
    )
    frontend = ROOT.parent / "frontend"
    assets = [
        (path, path.relative_to(frontend).as_posix())
        for path in frontend.rglob("*")
        if path.is_file() and path.suffix in {".html", ".js", ".css"}
    ]
    assets.extend(
        (ROOT / "frontend" / name, name) for name in ("admin.html", "admin.js", "admin.css")
    )
    for path, key in assets:
        content = (
            path.read_bytes()
            if path.name != "config.js"
            else (
                "window.SD_CONFIG = "
                + json.dumps({
                    "apiBase": api_base, "adminApiBase": "", "defaultApiMode": "real", "cloudwatchUrl": ""
                })
                + ";\n"
            ).encode()
        )
        content_type = {
            ".js": "application/javascript",
            ".css": "text/css",
            ".html": "text/html",
        }.get(path.suffix, mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        s3.put_object(
            Bucket=web,
            Key=key,
            Body=content,
            ContentType=content_type + "; charset=utf-8",
            CacheControl="no-cache",
            ServerSideEncryption="AES256",
        )
    csp = f"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' {api_base.rsplit('/prod', 1)[0]} https://{files}.s3.{REGION}.amazonaws.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://{files}.s3.{REGION}.amazonaws.com"
    security = {
        "StrictTransportSecurity": {
            "Override": True,
            "AccessControlMaxAgeSec": 31536000,
            "IncludeSubdomains": True,
        },
        "ContentTypeOptions": {"Override": True},
        "FrameOptions": {"Override": True, "FrameOption": "DENY"},
        "ReferrerPolicy": {"Override": True, "ReferrerPolicy": "no-referrer"},
        "ContentSecurityPolicy": {"Override": True, "ContentSecurityPolicy": csp},
    }
    if "response_headers_policy_id" not in STATE:
        result = cf.create_response_headers_policy(
            ResponseHeadersPolicyConfig={
                "Name": "securedrop-web-v13",
                "SecurityHeadersConfig": security,
            }
        )
        save(response_headers_policy_id=result["ResponseHeadersPolicy"]["Id"])
    else:
        current = cf.get_response_headers_policy(Id=STATE["response_headers_policy_id"])
        cf.update_response_headers_policy(
            Id=STATE["response_headers_policy_id"],
            IfMatch=current["ETag"],
            ResponseHeadersPolicyConfig={
                "Name": "securedrop-web-v13",
                "SecurityHeadersConfig": security,
            },
        )
    current = cf.get_distribution_config(Id=distribution)
    backup = OUT / "cloudfront-before-serverless.json"
    if not backup.exists():
        backup.write_text(json.dumps(current, indent=2), encoding="utf-8")
    dist = current["DistributionConfig"]
    dist["Origins"] = {
        "Quantity": 1,
        "Items": [
            {
                "Id": "securedrop-web",
                "DomainName": f"{web}.s3.{REGION}.amazonaws.com",
                "OriginPath": "",
                "ConnectionAttempts": 3,
                "ConnectionTimeout": 10,
                "CustomHeaders": {"Quantity": 0},
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "OriginAccessControlId": STATE["oac_id"],
            }
        ],
    }
    dist["DefaultRootObject"] = "index.html"
    dist["DefaultCacheBehavior"] = {
        "SmoothStreaming": False,
        "FieldLevelEncryptionId": "",
        "LambdaFunctionAssociations": {"Quantity": 0},
        "FunctionAssociations": {"Quantity": 0},
        "TrustedKeyGroups": {"Enabled": False, "Quantity": 0},
        "TargetOriginId": "securedrop-web",
        "ViewerProtocolPolicy": "redirect-to-https",
        "Compress": True,
        "AllowedMethods": {
            "Quantity": 2,
            "Items": ["GET", "HEAD"],
            "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
        },
        "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        "ResponseHeadersPolicyId": STATE["response_headers_policy_id"],
        "TrustedSigners": {"Enabled": False, "Quantity": 0},
    }
    dist["CacheBehaviors"] = {"Quantity": 0}
    configure_admin_origin(dist, api_base)
    cf.update_distribution(Id=distribution, IfMatch=current["ETag"], DistributionConfig=dist)
    invalidation = cf.create_invalidation(
        DistributionId=distribution,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/*"]},
            "CallerReference": str(time.time_ns()),
        },
    )
    save(invalidation_id=invalidation["Invalidation"]["Id"])
    log("CloudFront origin switched; wait for Deployed before verification and EC2 retirement")


if __name__ == "__main__":
    main()
