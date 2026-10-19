import json
import logging

from mangum import Mangum

from admin_diagnostics import gateway_metadata
from main import app

app.root_path = "/prod"
_adapter = Mangum(app, api_gateway_base_path="/prod", lifespan="off")
logger = logging.getLogger("securedrop")


def handler(event, context):
    is_admin = str(event.get("path", "")).startswith(("/api/admin/", "/prod/api/admin/"))
    metadata = gateway_metadata(event) if is_admin else {}
    if is_admin:
        logger.info(json.dumps({"event": "admin_lambda_received", **metadata}))
    try:
        response = _adapter(event, context)
    except Exception as exc:
        if is_admin:
            logger.error(
                json.dumps(
                    {
                        "event": "admin_lambda_failed",
                        **metadata,
                        "exception_type": type(exc).__name__,
                    }
                )
            )
        raise
    if is_admin:
        logger.info(
            json.dumps(
                {
                    "event": "admin_lambda_completed",
                    **metadata,
                    "status": response.get("statusCode"),
                }
            )
        )
    return response
