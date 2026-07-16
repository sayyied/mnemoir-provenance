# Scopes, privacy, and authority

Tenant, profile, project, session, actor, council, source, and global scopes are distinct typed boundaries. Privacy classes and grants are evaluated before retrieval or mutation. Status surfaces expose safe IDs, counts, hashes, and redacted pointers rather than raw private payloads.

Unknown scope or missing authority fails closed and emits a stable denial reason.
