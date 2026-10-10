# ADR 0002: replicated enterprise application model

**Status:** proposed

**Context.** The original repository scaffold described two unrelated
enterprises and fourteen application cells. The competition architecture
approved on 9 October instead uses one bank replicated as ENT-A and ENT-B,
with the same APP01–APP09 catalogue in each. Observability, deployment,
networking and scoring cannot correlate records while those identifiers differ.

**Decision.** Use `ENT-A` and `ENT-B` as enterprise IDs, `APP01` through
`APP09` as application IDs, and
`jengasec-<enterprise>-<application>` as namespaces. Both enterprise copies
use the same application catalogue. APP08 and APP09 are optional and are
enabled or disabled in both enterprises together. Application instances use
the reserved VLAN 108 addresses in the address contract.

Application stdout follows the version 2 logging contract. Observability maps
raw names through the shared catalogue and emits version 2 normalized
telemetry. Telemetry, platform audit and competition records remain separate;
evidence packs may reference all three without merging their schemas.

**Consequences.** The retired Zawadi/Afya and `app-NN` examples become invalid.
Existing unimplemented draft contracts and fixtures require replacement.
Platform allocation exports, namespaces and scope rows must adopt the new
identifiers before deployment. Optional applications need one symmetric
enablement decision. This ADR authorizes no Server 3, gateway or k3s change.
