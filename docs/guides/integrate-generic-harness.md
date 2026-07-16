# Integrate a generic harness

A host can export versioned JSON/JSONL events, ingest them through a controlled adapter, call cited recall, and inject a bounded context packet. The host maps its tenant/profile/project/session identities explicitly.

`examples/integrations/generic_cli_consumer.py` is the released non-Hermes proof. It uses only the CLI and synthetic data; it does not import Hermes or inspect a live session store.
