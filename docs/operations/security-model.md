# Security model

Default posture is local, explicit input, least authority, no silent promotion, no implicit live-store crawling, and no network listener except an explicitly launched loopback UI. Filesystem boundaries reject traversal, symlinks, special files, backup trees, and uncontrolled roots.

Mutations require policy and, for working-memory files, exact operation-bound authorization and read-back.
