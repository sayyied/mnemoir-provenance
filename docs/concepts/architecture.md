# Architecture

The core is an in-process Python library over local SQLite. Python and JSON CLI surfaces call the same domain operations. Controlled adapters ingest explicit exports. The loopback UI is a thin same-process view over canonical APIs. Markdown/wiki output is derived.

Trust boundaries and data flow are shown in `assets/diagrams/architecture.svg`; the editable source is beside it.
