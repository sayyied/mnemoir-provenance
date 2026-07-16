# Release verification

A release candidate must be generated twice from the same allowlisted input and compared, scanned as a tree and as wheel/sdist, installed under supported Python versions outside source checkouts, exercised through Python/CLI/non-Hermes/UI paths, and checked for docs/schema/version/package consistency. The history-free candidate is proposed through a review branch, and required Python 3.11/3.12 CI must pass on the exact candidate commit before merge or tag.

Release artifacts must be rebuilt from the authorized release commit, published with SHA-256 checksums, and bound to that commit in the release record. PyPI publication should use Trusted Publishing/OIDC rather than a long-lived upload token. Sigstore attestations are preferred when the release environment supports them. Public visibility, tags, package uploads, and announcements remain separate protected actions after candidate proof.
