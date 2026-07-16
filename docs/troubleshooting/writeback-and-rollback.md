# Writeback and rollback problems

Stale hash, expired/replayed authorization, path identity change, weak private-root permissions, and unknown post-image all fail closed. Use reconciliation to determine retry, rollback, or manual recovery.

Never copy backup bytes over the target outside the audited transaction path unless the documented manual-recovery procedure explicitly requires it.
