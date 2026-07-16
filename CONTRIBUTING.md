# Contributing

Contributions are welcome through the public project surface once a repository is opened. You do not need access to any private engineering repository.

1. Reproduce the issue with synthetic data.
2. Add or update focused tests.
3. Keep APIs fail-closed and status output leak-safe.
4. Run `python -m pytest -q` and `python -m build`.
5. Explain user-visible behavior, compatibility, and rollback.

Some files may be generated from a private canonical source. Maintainers will classify changes as core-generated, public-presentation, or both; backport accepted generated-core changes before convergence. Contributor authorship must be preserved. See `docs/contributing/public-projection-workflow.md`.
