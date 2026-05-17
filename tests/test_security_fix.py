from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from broker.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_validate_https_url_blocks_ipv6_loopback():
    """Regression test: urlparse strips brackets from [::1], blocklist must match."""
    from broker.services.discovery import _validate_https_url

    with pytest.raises(ValueError, match="private address"):
        _validate_https_url("https://[::1]/path", "test")


def test_validate_https_url_blocks_imds():
    """Block cloud metadata endpoint (AWS/GCP/Azure IMDS)."""
    from broker.services.discovery import _validate_https_url

    with pytest.raises(ValueError, match="private address"):
        _validate_https_url("https://169.254.169.254/latest/meta-data/", "test")


def test_validate_https_url_blocks_unspecified():
    """Block 0.0.0.0 — routes to 127.0.0.1 on Linux."""
    from broker.services.discovery import _validate_https_url

    with pytest.raises(ValueError, match="private address"):
        _validate_https_url("https://0.0.0.0/path", "test")


def test_unregistered_connector_returns_404(client):
    """Primary XSS defense: unregistered connector names hit 404, never reach HTML."""
    response = client.get("/oauth/bad<name>/callback?code=123&state=abc")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


def _broker_managed_connector() -> MagicMock:
    """Create a mock connector with auth_mode='broker' (not sidecar-managed)."""
    connector = MagicMock()
    connector.meta.is_sidecar_managed = False
    return connector


def test_oauth_callback_success_redirect_sanitization(client):
    """Connector name must be URL-encoded into the success redirect, not
    folded raw into the URL where it could inject query params or break
    URL parsing. The inline-HTML escape path was replaced with a redirect
    to a built-in /oauth/success page; sanitization happens at the URL
    boundary now (encoding) and inside the success page (isidentifier check)."""
    connector_name = "bad&connector<xss>"
    app_key = "test_app"

    mock_settings = MagicMock()
    mock_settings.broker.success_redirect_url = ""
    mock_settings.broker.public_url = "https://broker.example.com/"

    with (
        patch("broker.main._get_connector_or_404") as mock_get_connector,
        patch("broker.main._exchange_and_store_token", new_callable=AsyncMock) as mock_exchange,
        patch("broker.main._get_settings", return_value=mock_settings),
    ):
        mock_get_connector.return_value = _broker_managed_connector()
        mock_exchange.return_value = app_key

        response = client.get(
            f"/oauth/{connector_name}/callback?code=123&state=abc",
            follow_redirects=False,
        )

        assert response.status_code in (302, 307)
        location = response.headers["location"]
        # Raw special characters must not appear in the redirect URL; quote()
        # percent-encodes them so an attacker can't fold an extra `&` into the
        # query string to inject another param.
        assert "<" not in location
        assert ">" not in location
        # The encoded form is present
        assert "bad%26connector%3Cxss%3E" in location


def test_oauth_callback_value_error_sanitization(client):
    """Verify ValueError message is escaped in error HTML."""
    connector_name = "test_connector"
    error_msg = "Invalid token: <img src=x onerror=alert(1)>"

    with (
        patch("broker.main._get_connector_or_404") as mock_get_connector,
        patch("broker.main._exchange_and_store_token", new_callable=AsyncMock) as mock_exchange,
    ):
        mock_get_connector.return_value = _broker_managed_connector()
        mock_exchange.side_effect = ValueError(error_msg)

        response = client.get(f"/oauth/{connector_name}/callback?code=123&state=abc")

        assert response.status_code == 400
        assert "Authentication failed" in response.text
        assert error_msg not in response.text


def test_oauth_callback_exception_no_leak(client):
    """Verify generic Exception does NOT leak raw details to the user."""
    connector_name = "test_connector"

    with (
        patch("broker.main._get_connector_or_404") as mock_get_connector,
        patch("broker.main._exchange_and_store_token", new_callable=AsyncMock) as mock_exchange,
    ):
        mock_get_connector.return_value = _broker_managed_connector()
        mock_exchange.side_effect = Exception("Internal Database Error <script>")

        response = client.get(f"/oauth/{connector_name}/callback?code=123&state=abc")

        assert response.status_code == 500
        assert "Unexpected error — check broker logs." in response.text
        assert "<script>" not in response.text
