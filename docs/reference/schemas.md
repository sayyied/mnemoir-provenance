# Schemas

Released JSON schemas are in `schemas/`. The closed Hermes controlled-onboarding contract is `docs/reference/schemas/plugin-bootstrap-profile-result.schema.json`; validate every bootstrap success and failure envelope against it. The canonical SQL resource is packaged at `src/mnemoir_provenance/resources/0001_initial_schema.sql` and initialized by the library.

Consumers should reject fields according to each schema's compatibility policy. Bootstrap output intentionally excludes absolute paths, source text, snippets, credentials, and unrestricted metadata.
