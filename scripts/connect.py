"""
Interactive MCP connection manager.

Shows connector status with token health, lets you choose which to connect,
handles the OAuth flow (browser redirect + polling for callback).

Uses the admin API for key management and connect tokens — no plaintext
broker keys in YAML or URLs.

Architecture:
    _load_broker_settings() → Read settings.yaml + .env for admin_key
    _ensure_app_key()       → Check/create API key via admin API
    _show_status_table()    → Display connectors with connection/token state
    _choose_connector()     → Interactive connector selection
    _run_connect_flow()     → Create connect token + browser open + poll

Usage:
    python scripts/connect.py                          # Interactive (default app)
    python scripts/connect.py --app my_company:app1     # Specific app
    python scripts/connect.py --broker-url http://...   # Custom broker URL
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml
from dotenv import load_dotenv

logger_prefix = "  "  # Indent all output for readability

# =============================================================================
# CONSTANTS
# =============================================================================

_ENV_VAR_PATTERN = re.compile(r"^\$\{([^}]+)\}$")
_POLL_INTERVAL_SECONDS = 3
_POLL_TIMEOUT_SECONDS = 120
_HTTP_OK = 200
_HTTP_CREATED = 201
_HTTP_UNAUTHORIZED = 401
_HTTP_NOT_FOUND = 404
_HTTP_REDIRECT_CODES = (302, 307)
_BROKER_ROOT = Path(__file__).parent.parent


# =============================================================================
# SETTINGS
# =============================================================================


def _resolve_env_var_references(config_value: Any) -> Any:
    """Recursively resolve ${VAR} references from environment."""
    if isinstance(config_value, dict):
        return {k: _resolve_env_var_references(v) for k, v in config_value.items()}
    if isinstance(config_value, list):
        return [_resolve_env_var_references(v) for v in config_value]
    if isinstance(config_value, str):
        match = _ENV_VAR_PATTERN.match(config_value)
        if match:
            var_name = match.group(1)
            value = os.environ.get(var_name)
            if value is None:
                print(
                    f"{logger_prefix}Environment variable '{var_name}' not set"
                    " (required by settings.yaml)"
                )
                sys.exit(1)
            return value
    return config_value


def _load_broker_settings(settings_path: Path) -> dict[str, Any]:
    """Load and resolve settings.yaml with env var interpolation."""
    if not settings_path.exists():
        print(f"{logger_prefix}Settings file not found: {settings_path}")
        sys.exit(1)

    with open(settings_path) as f:
        raw = yaml.safe_load(f) or {}
    return _resolve_env_var_references(raw)


# =============================================================================
# ADMIN API
# =============================================================================


def _admin_request(  # noqa: PLR0913 — admin request needs all params
    broker_url: str, admin_key: str, method: str, path: str, json_body: dict | None = None
) -> httpx.Response:
    """Make an admin API request with X-Admin-Key header."""
    url = f"{broker_url}{path}"
    headers = {"x-admin-key": admin_key}
    return httpx.request(method, url, headers=headers, json=json_body, timeout=10.0)


def _find_broker_key_in_env() -> str | None:
    """Search environment for a br_* broker key.

    Checks a small list of common env var names.
    Returns the first valid-looking key found, or None.
    """
    candidate_vars = [
        "FG_CHAT_BROKER_KEY",
        "BROKER_KEY",
    ]
    for var_name in candidate_vars:
        value = os.environ.get(var_name, "")
        if value.startswith("br_"):
            return value
    return None


def _verify_broker_key(broker_url: str, app_key: str, broker_key: str) -> bool:
    """Verify a broker key works by hitting /status."""
    try:
        response = httpx.get(
            f"{broker_url}/status",
            headers={"x-app-id": app_key, "x-broker-key": broker_key},
            timeout=5.0,
        )
        return response.status_code == _HTTP_OK
    except httpx.RequestError:
        return False


def _ensure_app_key(broker_url: str, admin_key: str, app_key: str) -> str:  # noqa: PLR0915 — interactive flow with branching prompts
    """Ensure the app has an API key. Creates one if needed. Returns the raw key.

    Checks environment for existing br_* keys before prompting.
    If a key already exists in the database, prompts to rotate
    (since the raw key can't be retrieved from the broker).
    """
    # Check environment first — avoids prompting if key is already in .env
    env_key = _find_broker_key_in_env()
    if env_key and _verify_broker_key(broker_url, app_key, env_key):
        print(f"{logger_prefix}Using broker key from environment")
        return env_key

    # Check if key exists in broker database
    response = _admin_request(broker_url, admin_key, "GET", "/admin/keys")
    if response.status_code == _HTTP_UNAUTHORIZED:
        print(f"{logger_prefix}Admin key rejected — check BROKER_ADMIN_KEY in .env")
        sys.exit(1)

    apps = response.json().get("apps", [])
    app_entry = next((a for a in apps if a["app_key"] == app_key), None)

    if not app_entry:
        print(f"{logger_prefix}App '{app_key}' not found in broker's clients config")
        sys.exit(1)

    if app_entry.get("has_key"):
        if env_key:
            # Key was in env but didn't verify — stale or wrong key
            print(f"{logger_prefix}Broker key in environment is invalid (rejected by broker)")
        print(f"{logger_prefix}{app_key} already has an API key.")
        print(
            f"{logger_prefix}If you've lost the key, you can rotate it (invalidates the old one)."
        )
        choice = input(f"{logger_prefix}Rotate key? [y/N] ").strip().lower()
        if choice in ("y", "yes"):
            rotate_response = _admin_request(
                broker_url, admin_key, "POST", f"/admin/keys/{app_key}/rotate"
            )
            if rotate_response.status_code == _HTTP_OK:
                raw_key = rotate_response.json()["api_key"]
                print(f"{logger_prefix}Key rotated: {raw_key}")
                print(f"{logger_prefix}Update your MCP client config with this key.")
                return raw_key
            print(f"{logger_prefix}Rotate failed: {rotate_response.text}")
            sys.exit(1)
        # Use existing key — ask user to provide it
        print(f"{logger_prefix}Enter your existing broker key (or press Enter to skip status):")
        existing_key = input(f"{logger_prefix}Key: ").strip()
        if existing_key:
            return existing_key
        return ""

    # No key exists — create one
    create_response = _admin_request(
        broker_url, admin_key, "POST", "/admin/keys", {"app_key": app_key}
    )
    if create_response.status_code == _HTTP_CREATED:
        raw_key = create_response.json()["api_key"]
        print(f"{logger_prefix}API key created: {raw_key}")
        print(f"{logger_prefix}Save this key — it cannot be retrieved later.")
        return raw_key

    print(f"{logger_prefix}Failed to create key: {create_response.text}")
    sys.exit(1)


def _create_connect_token(broker_url: str, admin_key: str, app_key: str) -> str:
    """Create a single-use connect token for browser OAuth flow."""
    response = _admin_request(
        broker_url, admin_key, "POST", "/admin/connect-token", {"app_key": app_key}
    )
    if response.status_code == _HTTP_CREATED:
        return response.json()["connect_token"]

    print(f"{logger_prefix}Failed to create connect token: {response.text}")
    sys.exit(1)


# =============================================================================
# BROKER API
# =============================================================================


def _fetch_connectors(broker_url: str) -> list[dict[str, str]]:
    """GET /health — registered connectors with display names."""
    try:
        response = httpx.get(f"{broker_url}/health", timeout=5.0)
        if response.status_code == _HTTP_OK:
            return response.json().get("connectors", [])
    except httpx.RequestError:
        pass
    return []


def _fetch_connections(broker_url: str, app_key: str, broker_key: str) -> list[dict[str, Any]]:
    """GET /status — active connections with token health for an app."""
    if not broker_key:
        return []
    try:
        response = httpx.get(
            f"{broker_url}/status",
            headers={"x-app-id": app_key, "x-broker-key": broker_key},
            timeout=5.0,
        )
        if response.status_code == _HTTP_OK:
            return response.json().get("connections", [])
        if response.status_code == _HTTP_UNAUTHORIZED:
            print(f"{logger_prefix}Broker key rejected for /status — key may need rotation")
    except httpx.RequestError:
        pass
    return []


def _get_authorize_url(broker_url: str, connector_name: str, connect_token: str) -> str:
    """Hit /connect with a connect token and extract the OAuth redirect URL."""
    connect_url = f"{broker_url}/oauth/{connector_name}/connect?connect_token={connect_token}"

    response = httpx.get(connect_url, follow_redirects=False, timeout=15.0)

    if response.status_code in _HTTP_REDIRECT_CODES:
        location = response.headers.get("location")
        if location:
            return location

    if response.status_code == _HTTP_UNAUTHORIZED:
        print(f"{logger_prefix}Connect token rejected — it may have expired (5 min TTL)")
        sys.exit(1)
    if response.status_code == _HTTP_NOT_FOUND:
        print(f"{logger_prefix}Connector '{connector_name}' not found")
        sys.exit(1)

    print(f"{logger_prefix}Unexpected response: {response.status_code} {response.text}")
    sys.exit(1)


def _open_browser(url: str) -> None:
    """Open URL in default browser (macOS/Linux). Rejects non-HTTP(S) schemes."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        print(f"{logger_prefix}Refusing to open non-HTTP URL: {url}")
        return

    if sys.platform == "darwin":
        subprocess.run(["open", url], check=False)  # noqa: S603, S607 — trusted CLI opening validated URL
    elif sys.platform == "linux":
        subprocess.run(["xdg-open", url], check=False)  # noqa: S603, S607 — trusted CLI opening validated URL
    else:
        print(f"{logger_prefix}Open this URL manually:\n{logger_prefix}{url}")


def _poll_until_connected(
    broker_url: str, connector_name: str, app_key: str, broker_key: str
) -> bool:
    """Poll /status until the connector shows as connected or timeout."""
    start = time.time()

    while time.time() - start < _POLL_TIMEOUT_SECONDS:
        connections = _fetch_connections(broker_url, app_key, broker_key)
        is_connected = any(
            c.get("connector") == connector_name and c.get("connected") for c in connections
        )
        if is_connected:
            return True
        time.sleep(_POLL_INTERVAL_SECONDS)

    return False


# =============================================================================
# DISPLAY
# =============================================================================


def _format_token_status(connection: dict[str, Any] | None) -> tuple[str, str]:
    """Return (status_label, token_label) for a connection."""
    if connection is None:
        return "Not connected", "—"
    if connection.get("token_valid"):
        return "Connected", "Valid"
    return "Connected", "Expired"


def _show_status_table(
    connectors: list[dict[str, str]],
    connections: list[dict[str, Any]],
    app_key: str,
) -> list[tuple[dict[str, str], dict[str, Any] | None]]:
    """Display connector status table. Returns all connectors with connection info."""
    connected_by_name = {
        c["connector"]: c for c in connections if c.get("connected") and "connector" in c
    }

    print(f"\n{logger_prefix}MCP Connectors for {app_key}\n")
    print(f"{logger_prefix}{'#':<4}{'Connector':<20}{'Status':<15}{'Token'}")
    print(f"{logger_prefix}{'─' * 4}{'─' * 20}{'─' * 15}{'─' * 20}")

    all_connectors = []
    for i, connector in enumerate(connectors, 1):
        name = connector.get("name", "unknown")
        display_name = connector.get("display_name", name)
        connection = connected_by_name.get(name)
        status_label, token_label = _format_token_status(connection)
        all_connectors.append((connector, connection))
        print(f"{logger_prefix}{i:<4}{display_name:<20}{status_label:<15}{token_label}")

    print()
    return all_connectors


def _choose_connector(
    connectors_with_status: list[tuple[dict[str, str], dict[str, Any] | None]],
) -> tuple[str, bool] | None:
    """Interactive prompt to choose a connector. Returns (name, is_reconnect) or None."""
    if not connectors_with_status:
        print(f"{logger_prefix}No connectors registered.")
        return None

    print(f"{logger_prefix}Choose a connector:")
    for i, (connector, connection) in enumerate(connectors_with_status, 1):
        display_name = connector.get("display_name", connector["name"])
        status = "Connected" if connection else "Not connected"
        print(f"    {i}. {display_name} ({status})")
    print("    0. Exit")

    while True:
        try:
            raw_choice = input(f"\n{logger_prefix}Connect which? ").strip()
        except (ValueError, EOFError):
            return None

        if raw_choice in ("0", "q", "quit", "exit"):
            return None

        try:
            idx = int(raw_choice) - 1
        except ValueError:
            return None

        if 0 <= idx < len(connectors_with_status):
            connector, connection = connectors_with_status[idx]
            return (connector["name"], connection is not None)
        print(f"{logger_prefix}Enter 1-{len(connectors_with_status)} or 0 to exit")


# =============================================================================
# ORCHESTRATION
# =============================================================================


def _select_app_key(clients: dict[str, dict], cli_app: str | None) -> str:
    """Resolve which app_key to use — CLI arg or interactive selection."""
    if cli_app:
        return cli_app

    # Flatten clients config to compound keys
    app_keys = []
    for client_name, apps in clients.items():
        for app_name in apps:
            app_keys.append(f"{client_name}:{app_name}")

    if len(app_keys) == 1:
        return app_keys[0]

    print(f"\n{logger_prefix}Available apps:")
    for i, key in enumerate(app_keys, 1):
        print(f"    {i}. {key}")
    try:
        raw_choice = input(f"\n{logger_prefix}Select app: ")
        idx = int(raw_choice) - 1
        if 0 <= idx < len(app_keys):
            return app_keys[idx]
    except (ValueError, EOFError):
        pass
    sys.exit(0)


def _show_mcp_config(  # noqa: PLR0913 — display function needs all params
    broker_url: str,
    connector_name: str,
    app_key: str,
    broker_key: str,
    transport: str,
) -> None:
    """Print MCP server config for the connector.

    Output is JSON-like and directly usable by Claude Desktop, Claude Code,
    Cursor, Cline, and any other MCP client that accepts streamable-http
    servers. ADK users can translate to McpServerConfig(...) trivially.
    """
    _MASK_VISIBLE_CHARS = 4
    masked_key = (
        f"***{broker_key[-_MASK_VISIBLE_CHARS:]}"
        if len(broker_key) > _MASK_VISIBLE_CHARS
        else "****"
    )
    print(f"{logger_prefix}── {connector_name} ──")
    print(f'  "{connector_name}": {{')
    print(f'    "transport": "{transport}",')
    print(f'    "url": "{broker_url}/proxy/{connector_name}/mcp",')
    print('    "headers": {')
    print(f'      "X-App-Id": "{app_key}",')
    print(f'      "X-Broker-Key": "{masked_key}"')
    print("    }")
    print("  }\n")


def _get_connector_transport(broker_url: str, connector_name: str) -> str:
    """Fetch transport type for a connector from /health endpoint."""
    connectors = _fetch_connectors(broker_url)
    for c in connectors:
        if c.get("name") == connector_name:
            return c.get("transport", "streamable_http")
    return "streamable_http"


def _run_connect_flow(  # noqa: PLR0913 — connect flow needs all context
    broker_url: str,
    connector_name: str,
    app_key: str,
    broker_key: str,
    admin_key: str,
) -> None:
    """Create connect token, open browser, poll until connected."""
    print(f"\n{logger_prefix}Connecting {connector_name}...")

    # Create a single-use connect token (avoids raw key in URL)
    connect_token = _create_connect_token(broker_url, admin_key, app_key)
    authorize_url = _get_authorize_url(broker_url, connector_name, connect_token)

    print(f"{logger_prefix}Opening browser for OAuth consent...")
    _open_browser(authorize_url)
    print(f"{logger_prefix}If the browser didn't open, visit:\n{logger_prefix}{authorize_url}\n")

    print(f"{logger_prefix}Waiting for OAuth callback (timeout: {_POLL_TIMEOUT_SECONDS}s)...")
    if _poll_until_connected(broker_url, connector_name, app_key, broker_key):
        print(f"{logger_prefix}{connector_name} connected successfully!\n")
        transport = _get_connector_transport(broker_url, connector_name)
        _show_mcp_config(broker_url, connector_name, app_key, broker_key, transport)
    else:
        print(f"{logger_prefix}Timed out waiting for {connector_name} connection.")
        print(f"{logger_prefix}Check the broker logs and try again.")
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(description="Interactive MCP connection manager")
    parser.add_argument(
        "--app",
        default=None,
        help="App key (e.g. my_company:app1). Prompts if multiple apps configured.",
    )
    parser.add_argument(
        "--broker-url",
        default=os.environ.get("BROKER_URL", "http://localhost:8002"),
        help="Broker URL (env: BROKER_URL, default: http://localhost:8002)",
    )
    parser.add_argument(
        "--settings",
        default=None,
        help="Path to settings.yaml (default: ./settings.yaml)",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show MCP server config for connected connectors (no OAuth flow)",
    )
    return parser


def _select_connector_with_status(
    connectors: list[dict[str, str]],
    connections: list[dict[str, Any]],
    app_key: str,
) -> str | None:
    """Show status table, prompt for choice, warn on reconnect."""
    all_connectors = _show_status_table(connectors, connections, app_key)
    choice = _choose_connector(all_connectors)
    if not choice:
        return None

    connector_name, is_reconnect = choice
    if is_reconnect:
        display_name = next(
            (c.get("display_name", c["name"]) for c in connectors if c["name"] == connector_name),
            connector_name,
        )
        print(
            f"{logger_prefix}{display_name} is already connected"
            " — this will replace the existing token."
        )

    return connector_name


def _show_all_configs(
    broker_url: str,
    connections: list[dict[str, Any]],
    app_key: str,
    broker_key: str,
) -> None:
    """Print MCP config snippets for all connected connectors and exit."""
    connected = [c for c in connections if c.get("connected")]
    if not connected:
        print(f"{logger_prefix}No connected connectors for {app_key}")
        print(f"{logger_prefix}Run ./start connect first to set up OAuth")
        sys.exit(1)
    print(f"\n{logger_prefix}MCP server config for {app_key}:\n")
    for conn in connected:
        name = conn.get("connector", "unknown")
        transport = _get_connector_transport(broker_url, name)
        _show_mcp_config(broker_url, name, app_key, broker_key, transport)


def main() -> None:  # noqa: PLR0915 — CLI entry point with sequential setup steps
    load_dotenv(_BROKER_ROOT / ".env")
    args = _build_parser().parse_args()

    settings_path = Path(args.settings) if args.settings else _BROKER_ROOT / "settings.yaml"
    settings = _load_broker_settings(settings_path)

    # Get admin key from settings
    admin_key = settings.get("broker", {}).get("admin_key", "")
    if not admin_key:
        print(f"{logger_prefix}No admin_key configured in settings.yaml")
        sys.exit(1)

    # Select app from clients config
    clients = settings.get("clients", {})
    if not clients:
        print(f"{logger_prefix}No clients configured in settings.yaml")
        sys.exit(1)
    app_key = _select_app_key(clients, args.app)

    # Check broker is reachable
    connectors = _fetch_connectors(args.broker_url)
    if not connectors:
        print(f"{logger_prefix}Could not reach broker at {args.broker_url}")
        print(f"{logger_prefix}Start it with: ./start start")
        sys.exit(1)

    # Ensure the app has an API key (creates one if needed)
    broker_key = _ensure_app_key(args.broker_url, admin_key, app_key)

    connections = _fetch_connections(args.broker_url, app_key, broker_key)

    if args.show_config:
        if not broker_key:
            print(f"{logger_prefix}No broker key available — rotate or create one first")
            sys.exit(1)
        _show_all_configs(args.broker_url, connections, app_key, broker_key)
        return

    connector_name = _select_connector_with_status(connectors, connections, app_key)
    if not connector_name:
        return

    _run_connect_flow(args.broker_url, connector_name, app_key, broker_key, admin_key)


if __name__ == "__main__":
    main()
