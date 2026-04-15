# Connector Templates

Minimum-viable scaffolding for each of the four connector flavours. Copy the directory that matches your provider's OAuth model and fill in the `TODO` markers.

| Flavour | When to use | Start here |
|---------|-------------|------------|
| **Static** | Remote MCP server with fixed OAuth endpoints (e.g. HubSpot) | `static/` |
| **Discovery** | Remote MCP server supporting RFC 8414 + RFC 7591 (e.g. Notion) | `discovery/` |
| **Sidecar** | MCP server you run as a local container (e.g. Google Workspace) | `sidecar/` + `sidecars/_template/` |
| **Native** | No MCP server exists; wrap a Python SDK / REST API in-process (e.g. Twitter/X) | `native/` |

Don't know which flavour you need? Follow the `Provider Onboarding` algorithm in [AGENTS.md](../../../AGENTS.md#provider-onboarding).

## Steps for every flavour

1. `cp -r _template/{flavour} {name}/` — pick a short snake_case `{name}`.
2. Rename the class in `adapter.py` (e.g. `TemplateStaticConnector` → `JiraConnector`).
3. Fill in the `TODO` markers in `adapter.py` and `SETUP.md`.
4. Add `{name}` to `broker.connectors` in `settings.example.yaml`.
5. For Static: add `{NAME}_CLIENT_ID` and `{NAME}_CLIENT_SECRET` to `.env.example`, and an entry under the `apps` section of `settings.example.yaml`.
6. Add a test at `tests/test_{name}_connector.py`.
7. Run `pytest tests/test_{name}_connector.py -v` — must pass before PR.

See [AGENTS.md](../../../AGENTS.md#connector-rules-must) for the full invariant list reviewers will check.
