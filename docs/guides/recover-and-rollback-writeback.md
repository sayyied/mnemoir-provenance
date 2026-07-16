# Recover and roll back writeback

Reconciliation inspects the operation journal, authenticated pending evidence, target hash, and read-back state. It may finish evidence commit, report retry-with-new-authorization, require rollback, or require manual recovery. Unknown target hashes fail closed.

Rollback is a new authorized transaction bound to the original operation and exact post-image hash. It restores the private pre-image, reads back, reconciles evidence, and consumes rollback availability.
