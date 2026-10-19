import json
import logging

import pytest

from admin_diagnostics import gateway_metadata


@pytest.mark.parametrize("header_name", ["Authorization", "authorization", "AUTHORIZATION"])
def test_gateway_metadata_reports_both_header_maps_without_values(header_name):
    secret = "Bearer private-session-token"
    metadata = gateway_metadata(
        {
            "headers": {header_name: secret},
            "multiValueHeaders": {header_name: [secret]},
            "requestContext": {"requestId": "gateway-request"},
        }
    )
    assert metadata["authorization_single_present"]
    assert metadata["authorization_multi_present"]
    assert metadata["authorization_single_bearer"]
    assert metadata["authorization_multi_bearer"]
    assert metadata["gateway_request_id"] == "gateway-request"
    assert secret not in json.dumps(metadata)
    assert "private-session-token" not in json.dumps(metadata)


def test_lambda_wrapper_logs_entry_and_completion_without_secrets(monkeypatch, caplog):
    import handler

    event = {
        "path": "/prod/api/admin/login",
        "resource": "/api/admin/login",
        "httpMethod": "POST",
        "headers": {"authorization": "Bearer private-token"},
        "body": '{"password":"private-password"}',
        "requestContext": {"requestId": "gateway-request"},
    }
    monkeypatch.setattr(handler, "_adapter", lambda event, context: {"statusCode": 200})
    with caplog.at_level(logging.INFO, logger="securedrop"):
        assert handler.handler(event, {}) == {"statusCode": 200}
    records = [json.loads(record.message) for record in caplog.records]
    assert [record["event"] for record in records] == [
        "admin_lambda_received",
        "admin_lambda_completed",
    ]
    assert all(record["gateway_request_id"] == "gateway-request" for record in records)
    assert "private-token" not in caplog.text
    assert "private-password" not in caplog.text
