# Release process

Freeze identity/version, export twice, verify output sets/hashes, build wheel/sdist, run clean installs and quickstarts under supported Python, run non-Hermes and UI proof, scan tree/archives, validate docs/schemas/licenses/dependencies, and record residual risk. Push the history-free candidate to a review branch in the private staging repository, require Python 3.11/3.12 CI on the exact candidate commit, and merge only after review.

After explicit launch authorization, rebuild artifacts from the authorized release commit, publish SHA-256 checksums, prefer PyPI Trusted Publishing/OIDC and Sigstore attestations, create the tag/release, and verify registry installation. Do not change public visibility, tag, upload, or announce during candidate construction.
