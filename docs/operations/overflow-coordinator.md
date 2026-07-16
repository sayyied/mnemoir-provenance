# Overflow coordinator

The coordinator enumerates only explicitly configured targets, isolates each profile/target operation, returns per-target and aggregate status, and makes partial failure visible. It reconciles recoverable operations before new work.

Keep it disabled until target discovery, policy, private journal permissions, and authorization issuer are configured. Scheduling or host-service persistence is outside the package.
