"""Safe request metadata for diagnosing administrator authentication delivery."""


def gateway_metadata(event):
    single = event.get("headers") or {}
    multi = event.get("multiValueHeaders") or {}
    single_auth = [v for k, v in single.items() if k.lower() == "authorization"]
    multi_auth = [v for k, v in multi.items() if k.lower() == "authorization"]
    return {
        "gateway_request_id": (event.get("requestContext") or {}).get("requestId"),
        "http_method": event.get("httpMethod"),
        "resource": event.get("resource"),
        "authorization_single_present": bool(single_auth),
        "authorization_multi_present": bool(multi_auth),
        "authorization_single_bearer": any(
            isinstance(v, str) and v.lower().startswith("bearer ") for v in single_auth
        ),
        "authorization_multi_bearer": any(
            isinstance(v, list)
            and any(isinstance(x, str) and x.lower().startswith("bearer ") for x in v)
            for v in multi_auth
        ),
        "authorization_remapped_present": any(
            k.lower() == "x-amzn-remapped-authorization" for k in (*single, *multi)
        ),
    }
