# """Normalization and cross-referencing of vulnerabilities against CISA KEV."""

# from __future__ import annotations

# # from packsafe.evidence.collectors.kev import KEVCollector
# # from packsafe.evidence.models import VulnerabilityItem


# class KEVNormalizer:
#     """Normalizes active exploitation evidence using the CISA KEV catalog."""

#     def __init__(self, collector: KEVCollector | None = None) -> None:
#         self.collector = collector or KEVCollector()

#     def enrich_vulnerabilities(
#         self,
#         items: tuple[VulnerabilityItem, ...] | list[VulnerabilityItem],
#     ) -> list[VulnerabilityItem]:
#         """Checks vulnerability IDs and aliases against KEV, updating actively_exploited."""
#         catalog = self.collector.fetch_catalog()
#         enriched: list[VulnerabilityItem] = []

#         for item in items:
#             is_exploited = item.actively_exploited
#             all_ids = [item.vulnerability_id] + list(item.aliases)

#             for cand_id in all_ids:
#                 norm_id = cand_id.strip().upper()
#                 if norm_id in catalog:
#                     is_exploited = True
#                     break

#             enriched.append(
#                 VulnerabilityItem(
#                     vulnerability_id=item.vulnerability_id,
#                     aliases=item.aliases,
#                     severity=item.severity,
#                     exploitability=1.0 if is_exploited else item.exploitability,
#                     exposure=item.exposure,
#                     actively_exploited=is_exploited,
#                     affected_ranges=item.affected_ranges,
#                     fixed_versions=item.fixed_versions,
#                     summary=item.summary,
#                     source=item.source,
#                     applicability_status=item.applicability_status,
#                 )
#             )

#         return enriched
