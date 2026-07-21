# Installation problems

Confirm Python 3.11/3.12 and a fresh virtual environment. The PyPI name is `mnemoir-provenance`, command is `mnemoir`, import is `mnemoir_provenance`. Run `python -m pip check`, `python -c "import mnemoir_provenance; print(mnemoir_provenance.__version__)"`, and `mnemoir --version`. Base standalone/generic use must work before adding extras.

For Hermes, do not repair a wrong interpreter by installing another Hermes into an unrelated environment. Run `mnemoir plugin status --hermes-home <HOME> --hermes-python <HERMES_PYTHON>`. `package_not_importable_in_hermes_runtime` means install `mnemoir-provenance[hermes]` with that exact interpreter. `default_storage_parent_unsafe` means rerun the explicit installer against the exact home; do not manually create the default parent. `custom_db_parent_missing` requires the operator to create and secure the custom parent explicitly.
