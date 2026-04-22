# Contributing to mcp-broker

Thanks for considering a contribution. This project is maintained by [Firney](https://firney.com) and welcomes community contributions.

## Reporting Issues

- **Security issues**: Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
- **Bugs**: Use the bug-report issue template. Include a minimal reproducer, expected vs. actual behaviour, and environment details (Python version, OS, broker version).
- **Feature requests**: Use the feature-request template. Describe the problem you're trying to solve before proposing a specific solution.

For larger changes, open an issue **before** sending a PR so we can align on scope.

## Development Setup

Requires Python 3.11+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/FirneyGroup/mcp-broker.git
cd mcp-broker
uv sync --extra dev
cp settings.example.yaml settings.yaml
cp .env.example .env
# Generate BROKER_ENCRYPTION_KEY, BROKER_ADMIN_KEY, BROKER_STATE_SECRET per .env.example
./start start
```

## Pull Request Process

1. Fork the repository and create a branch from `main`. Branch names: `fix/...`, `feat/...`, `docs/...`.
2. Make your changes, following the code style below.
3. Add or update tests. New functionality must include tests. Bug fixes should include a regression test.
4. Ensure all checks pass locally:
   ```bash
   uv run ruff check .
   uv run ruff format --check .
   uv run pyright
   uv run pytest tests/ -v
   ```
5. Commit in [Conventional Commits](https://www.conventionalcommits.org/) format — `<type>(<scope>): <description>`. One logical change per commit. See [AGENTS.md](AGENTS.md#commit-messages-must) for the allowed types, scopes, and the `!` marker for breaking changes. Do not reference AI assistants or Claude in commit messages.
6. Update `CHANGELOG.md` under `[Unreleased]` with a one-line bullet per user-visible change. Describe the impact, not the implementation — scope lists, cache internals, and refactor rationale belong in code docstrings or [AGENTS.md](AGENTS.md), not the changelog.
7. Open a PR using the pull-request template. Fill every section — "not applicable" is a valid answer, empty is not.

CI runs linting and the full test suite on every PR. PRs must be green before review.

## Code Style

- **Formatter**: `ruff format` (enforced in CI). No style debates — the formatter is the style guide.
- **Linter**: `ruff check` with the rule set in `pyproject.toml`. Security rules (`S`) are on — exceptions need `# noqa` with inline justification.
- **Types**: `pyright` strict on new code. Every public signature fully annotated.
- **Functions**: 25 lines max, 4 arguments max (including `self`), 3 levels of nesting max. Extract helpers when you hit the limit.
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes. Verb-noun for functions (`validate_token`, `fetch_user`). Booleans with `is_`/`has_`/`should_` prefix.
- **Comments**: Comment *why*, not *what*. If a mid-level engineer can't understand why a block exists in 30 seconds, add a comment.
- **Pydantic, not dataclasses**: All models use `BaseModel`; immutable configs use `ConfigDict(frozen=True)`.
- **Errors**: Raise from the layer that detects the issue. Top-level handlers convert to responses. Minimum `try` scope — only wrap the line that raises.
- **Logging**: Module-level `logger = logging.getLogger(__name__)`. Never log secrets, tokens, keys, or credentials.

## Adding a Connector

See the [Adding a Connector](README.md#adding-a-connector) section in the README. Every new connector must include:

- `src/connectors/{name}/adapter.py` — the `BaseConnector` subclass
- `src/connectors/{name}/SETUP.md` — OAuth setup instructions following the pattern of existing connectors
- Unit tests covering auto-registration, OAuth config, and any overridden hooks
- If static OAuth: credentials in `settings.example.yaml` as placeholders
- If discovery-based: set `mcp_oauth_url` and no credentials needed

## Security & Hooks

- Pre-commit hooks (`.pre-commit-config.yaml`) run `ruff`, `gitleaks`, YAML/TOML validation, and lockfile checks. Install with `pre-commit install`.
- **Never bypass hooks** with `--no-verify`. If a hook fails, fix the cause. If you believe a hook is wrong, open an issue.
- The broker stores OAuth tokens — treat any change touching `src/broker/services/store.py`, `oauth.py`, `middleware/auth.py`, or `api/admin.py` with extra care. PRs in these areas should include threat-model reasoning in the description.

## Maintainer

This project is stewarded by [Firney](https://firney.com). Contact `dev@firney.com` for commercial support enquiries. For security issues, use `security@firney.com` (see [SECURITY.md](SECURITY.md)).
