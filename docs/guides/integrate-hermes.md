# Integrate the Hermes reference adapter

Hermes integration is optional. Install the `hermes` extra, place the packaged plugin only into an explicitly supplied controlled Hermes home, select the provider through normal Hermes configuration, and verify cited/degraded behavior before enabling any maintenance feature.

The adapter supports profile-scoped recall/context, controlled completed-turn proposals, controlled profile Markdown ingestion, overflow pressure, and separately configured live writeback. It never needs a Honcho API. Installation does not restart gateways or alter provider configuration. Disable by deselecting/removing the plugin while retaining the canonical database according to policy.
