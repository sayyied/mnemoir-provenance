# Write a working-memory adapter

A working-memory adapter declares targets, units, capacity/warning/trigger/target policy, block serialization, ownership/path boundaries, lock strategy, backup/transaction storage, authorization issuer, evidence preservation, redaction, and recovery.

Implement discover, read snapshot, measure, split/render, authorize, atomic replace, reconcile, and rollback. Do not advertise an adapter until its exact target and clean-room transaction paths pass.
