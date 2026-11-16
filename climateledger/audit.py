from __future__ import annotations

from collections import Counter
from hashlib import sha256
from typing import Any

from .intake import canonical_bytes
from .registry import ContractError


class AuditInspector:
    def __init__(self, store, registry, releases):
        self.store = store
        self.registry = registry
        self.releases = releases

    def batch_trace(self, batch_id: int) -> dict[str, Any]:
        batch = self.store.batch(batch_id)
        rows = self.store.measurements(batch_id)
        events = self.store.events(f"batch:{batch_id}")
        if len(rows) > batch["row_count"]:
            raise ContractError("batch_corrupt", "stored measurements exceed declared rows")
        ordered_lines = [row["line"] for row in rows]
        if len(set(ordered_lines)) != len(ordered_lines):
            raise ContractError("batch_corrupt", "duplicate line numbers")
        if any(line < 1 or line > batch["row_count"] for line in ordered_lines):
            raise ContractError("batch_corrupt", "stored line exceeds declared row count")
        findings = Counter(item["code"] for item in batch["findings"])
        return {"batch": {key: batch[key] for key in (
                    "id", "source", "external_id", "revision", "payload_hash", "status", "row_count")},
                "measurement_count": len(rows), "finding_codes": dict(findings),
                "event_count": len(events), "events": events,
                "line_digest": sha256(canonical_bytes(ordered_lines)).hexdigest()}

    def release_trace(self, version: int) -> dict[str, Any]:
        bundle = self.releases.export(version)
        lineage = self.releases.lineage(version)
        batches = sorted({entry["batch_id"] for entry in bundle["entries"]})
        source_keys = sorted({entry["source"] for entry in bundle["entries"]})
        indicator_keys = sorted({entry["indicator"] for entry in bundle["entries"]})
        # 发布时记录的许可遮蔽是有意为之，不属于数据损坏；审计据此区分两者。
        restrictions = self.store.release_restrictions(version)
        masked_keys = {(item["source"], item["indicator"], item["period"]) for item in restrictions}
        missing = []
        masked_count = 0
        for entry in bundle["entries"]:
            entry_key = entry["source"], entry["indicator"], entry["period"]
            if entry_key in masked_keys:
                if entry["value"] is not None:
                    missing.append({"entry": entry, "reason": "mask_not_applied"})
                else:
                    masked_count += 1
                continue
            if entry["value"] is None:
                # 条目被遮蔽却没有对应的限制记录：限制表被篡改或数据损坏。
                missing.append({"entry": entry, "reason": "unrecorded_mask"})
                continue
            batch = self.store.batch(entry["batch_id"])
            if batch["source"] != entry["source"]:
                missing.append({"entry": entry, "reason": "source_mismatch"})
                continue
            rows = self.store.measurements(entry["batch_id"])
            if not any(row["line"] == entry["line"] and row["indicator"] == entry["indicator"]
                       and row["period"] == entry["period"] and row["value"] == entry["value"]
                       for row in rows):
                missing.append({"entry": entry, "reason": "measurement_mismatch"})
        # 清单声明的许可限制必须与持久化限制表完全一致，防止任一侧被篡改。
        manifest_keys = {(item["source"], item["indicator"], item["period"])
                         for item in bundle["manifest"].get("license_restrictions", [])}
        if manifest_keys != masked_keys:
            missing.append({"reason": "restriction_table_mismatch",
                            "manifest_only": sorted(manifest_keys - masked_keys),
                            "table_only": sorted(masked_keys - manifest_keys)})
        return {"version": version, "verified": not missing and self.releases.verify(bundle),
                "digest": bundle["digest"], "lineage": lineage,
                "batch_ids": batches, "sources": source_keys, "indicators": indicator_keys,
                "entry_count": len(bundle["entries"]), "masked_count": masked_count,
                "broken_entries": missing}

    def license_trace(self) -> dict[str, Any]:
        """审计授权决策流：重放安全、作用域合法、发布限制均能回溯到真实决策。"""
        decisions = self.store.list_license_decisions()
        notifications = [row["notification_id"] for row in decisions]
        duplicate_notifications = [notification for notification in set(notifications)
                                   if notifications.count(notification) > 1]
        # 每条发布限制必须引用一条真实存在的撤销决策。
        dangling = []
        restriction_total = 0
        latest = self.store.latest_release()
        if latest:
            decision_ids = {row["id"] for row in decisions}
            for version in range(1, latest["version"] + 1):
                for restriction in self.store.release_restrictions(version):
                    restriction_total += 1
                    if restriction["decision_id"] not in decision_ids:
                        dangling.append({"version": version, "restriction": restriction})
        return {"decision_count": len(decisions),
                "duplicate_notifications": sorted(duplicate_notifications),
                "restriction_total": restriction_total,
                "dangling_restrictions": dangling,
                "decisions": decisions,
                "verified": not duplicate_notifications and not dangling}

    def inspect_all(self) -> dict[str, Any]:
        batches = self.store.list_batches()
        latest = self.store.latest_release()
        batch_traces = [self.batch_trace(batch["id"]) for batch in batches]
        releases = []
        if latest:
            releases = [self.release_trace(version) for version in range(1, latest["version"] + 1)]
        violations = [entry for entry in releases if not entry["verified"]]
        license_trace = self.license_trace()
        if not license_trace["verified"]:
            violations.append({"license_audit": license_trace})
        return {"batch_count": len(batches), "release_count": len(releases),
                "violations": violations, "batch_traces": batch_traces,
                "release_digests": [release["digest"] for release in releases],
                "license_audit": {key: license_trace[key] for key in (
                    "decision_count", "restriction_total", "duplicate_notifications",
                    "dangling_restrictions", "verified")}}
