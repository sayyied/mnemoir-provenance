# Configuration

Configuration precedence is explicit CLI argument, environment variable, then documented default. Core variables use the `MNEMOIR_` prefix. Important settings are database path, controlled source root, retrieval mode/limit/context budget, projection root, and loopback UI host/port.

Live writeback is not enabled by a general flag. A host adapter must declare targets and policy; each mutation needs operation-bound authorization and exact preconditions.
