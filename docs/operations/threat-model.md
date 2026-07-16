# Threat model

Threats include malicious source text, path traversal/symlink races, archive tricks, SQLite contention, stale authorization, capability leakage, hostile loopback requests, prompt injection in imported content, accidental projection feedback, and supply-chain dependency compromise.

Controls include controlled roots, no-follow reads, exact path/host/origin checks, bounded bodies, CSP, per-process mutation token, typed scope, redacted errors, private transaction permissions, CAS hashes, atomic replacement where supported, fsync/read-back, receipts, and independent artifact scanning. Residual risk remains for compromised user accounts, unsupported filesystems, malicious dependencies, and operator misconfiguration.
