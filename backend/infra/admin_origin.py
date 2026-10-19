"""Route administrator API requests through the website's CloudFront domain."""

from urllib.parse import urlsplit


def configure_admin_origin(distribution, api_base):
    api = urlsplit(api_base)
    origin = {
        "Id": "securedrop-admin-api",
        "DomainName": api.netloc,
        "OriginPath": api.path.rstrip("/"),
        "CustomHeaders": {"Quantity": 0},
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
        "ConnectionAttempts": 3,
        "ConnectionTimeout": 10,
    }
    origins = [o for o in distribution["Origins"]["Items"] if o["Id"] != origin["Id"]]
    origins.append(origin)
    distribution["Origins"] = {"Quantity": len(origins), "Items": origins}
    behavior = {
        "PathPattern": "/api/admin/*",
        "TargetOriginId": origin["Id"],
        "ViewerProtocolPolicy": "https-only",
        "AllowedMethods": {
            "Quantity": 7,
            "Items": ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "POST", "DELETE"],
            "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
        },
        "Compress": True,
        # CachingDisabled and AllViewerExceptHostHeader forward Authorization and
        # query parameters while using API Gateway's host for origin routing.
        "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
        "TrustedSigners": {"Enabled": False, "Quantity": 0},
        "TrustedKeyGroups": {"Enabled": False, "Quantity": 0},
        "LambdaFunctionAssociations": {"Quantity": 0},
        "FunctionAssociations": {"Quantity": 0},
        "SmoothStreaming": False,
        "FieldLevelEncryptionId": "",
    }
    behaviors = [
        b
        for b in distribution.get("CacheBehaviors", {}).get("Items", [])
        if b["PathPattern"] != behavior["PathPattern"]
    ]
    behaviors.insert(0, behavior)
    distribution["CacheBehaviors"] = {"Quantity": len(behaviors), "Items": behaviors}
