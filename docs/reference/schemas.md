# Schemas

Released JSON schemas are in `schemas/`. The canonical SQL resource is packaged at `src/mnemoir_provenance/resources/0001_initial_schema.sql` and initialized by the library. Event and envelope schemas are versioned.

Consumers should reject unknown required fields only according to each schema's compatibility policy and preserve unknown metadata when documented.
