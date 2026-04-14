## Summary

<!-- One paragraph describing what this PR does and why -->

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] New connector
- [ ] Documentation
- [ ] Refactor / cleanup

## Related Issue

<!-- Link to the issue this PR addresses. Use "Closes #123" to auto-close on merge. -->

## Testing

<!-- How did you verify this works? Include concrete steps a reviewer can repeat. -->

- [ ] Unit tests added / updated
- [ ] Manual testing steps listed below
- [ ] `uv run pytest tests/ -v` passes locally
- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format --check .` passes

<!-- Manual testing steps: -->

## Breaking Changes

<!-- If this PR breaks any existing behaviour, describe the migration path. Otherwise write "None." -->

## Security Considerations

<!-- Required for PRs touching src/broker/services/store.py, oauth.py, middleware/auth.py, or api/admin.py. Describe threat model impact. Otherwise write "None." -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] I have added docstrings for any new public functions / classes
- [ ] I have updated the README if user-facing behaviour changed
- [ ] I have not referenced AI assistants in the commit messages
