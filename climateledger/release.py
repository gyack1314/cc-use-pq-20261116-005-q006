from __future__ import annotations

from hashlib import sha256
from typing import Any

from .intake import canonical_bytes
from .registry import ContractError


# 遮蔽后的占位值；清单中同时给出被限制范围，消费方不会误当作真实观测。
MASKED_VALUE = None
MASKED_UNIT = "restricted"


class ReleaseBuilder:
    def __init__(self, store, licensing=None):
        self.store = store
        self.licensing = licensing

    def preview(self, batch_id: int, expected_revision: int) -> dict[str, Any]:
        batch = self.store.batch(batch_id)
        if batch["revision"] != expected_revision:
            raise ContractError("stale_revision", "expected revision differs")
        if batch["status"] not in {"accepted", "approved", "published"}:
            raise ContractError("quality_gate", "batch has unresolved quality findings")
        latest = self.store.latest_batch(batch["source"], batch["external_id"])
        if latest["id"] != batch_id and batch["status"] != "published":
            raise ContractError("stale_revision", "newer revision supersedes this batch")
        if batch["published_version"]:
            return self.store.release(batch["published_version"])["manifest"]
        prior = self.store.latest_release()
        version = prior["version"] + 1 if prior else 1
        entries = self._entries(batch_id, prior["version"] if prior else None)
        restrictions = self._restrictions(entries)
        return self._manifest(batch, version, entries, prior, restrictions)

    def _measurement_origin(self, source: str, indicator: str, period: str) -> dict[str, Any] | None:
        """从底层测量表重建某条出处的真实值（用于解除遮蔽后恢复）。"""
        connection = self.store.connection
        row = connection.execute(
            "SELECT m.* FROM measurements m JOIN batches b ON b.id=m.batch_id "
            "WHERE b.source=? AND m.indicator=? AND m.period=? "
            "ORDER BY b.revision DESC, m.line LIMIT 1",
            (source, indicator, period)).fetchone()
        if row is None:
            return None
        return {"source": source, "indicator": indicator, "period": period,
                "batch_id": row["batch_id"], "line": row["line"],
                "value": row["value"], "unit": row["unit"]}

    def _entries(self, batch_id: int, prior_version: int | None) -> list[dict[str, Any]]:
        batch = self.store.batch(batch_id)
        entries: dict[tuple[str, str, str], dict[str, Any]] = {}
        if prior_version:
            prior_restrictions = {
                (item["source"], item["indicator"], item["period"])
                for item in self.store.release_restrictions(prior_version)}
            for item in self.store.release_entries(prior_version):
                key = item["source"], item["indicator"], item["period"]
                was_masked = key in prior_restrictions
                currently_restricted = self.licensing is not None and \
                    self.licensing.restriction_for(item["source"], item["indicator"], item["period"]) is not None
                if was_masked and not currently_restricted:
                    # 许可已恢复：丢弃遮蔽占位，从底层测量重建真实出处。
                    restored = self._measurement_origin(item["source"], item["indicator"], item["period"])
                    if restored is not None:
                        entries[key] = restored
                    continue
                entries[key] = {field: item[field] for field in (
                    "source", "indicator", "period", "batch_id", "line", "value", "unit")}
        for item in self.store.measurements(batch_id):
            key = batch["source"], item["indicator"], item["period"]
            entries[key] = {"source": batch["source"], "indicator": item["indicator"],
                            "period": item["period"], "batch_id": batch_id, "line": item["line"],
                            "value": item["value"], "unit": item["unit"]}
        return [entries[key] for key in sorted(entries)]

    def _restrictions(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """发布前对每条出处执行许可检查，返回需要写进清单的限制决定。"""
        if self.licensing is None:
            return []
        restrictions = []
        for entry in entries:
            restriction = self.licensing.restriction_for(
                entry["source"], entry["indicator"], entry["period"])
            if restriction is None:
                continue
            decision = self._decision_for(entry["source"], restriction["notification_id"])
            if restriction["mode"] == "stop":
                raise ContractError(
                    "license_withheld",
                    f"export stopped: {entry['source']}/{entry['indicator']}/{entry['period']} "
                    f"is under a stop restriction (notification {restriction['notification_id']})")
            restrictions.append({"source": entry["source"], "indicator": entry["indicator"],
                                 "period": entry["period"], "mode": "mask",
                                 "decision_id": decision["id"],
                                 "notification_id": restriction["notification_id"],
                                 "reason": restriction["reason"],
                                 "effective_at": restriction["effective_at"],
                                 "scope": restriction["scope"]})
        return restrictions

    def _decision_for(self, source: str, notification_id: str) -> dict[str, Any]:
        for row in self.store.list_license_decisions(source):
            if row["notification_id"] == notification_id:
                return row
        raise ContractError("license_state_corrupt",
                            f"no stored decision for notification {notification_id}")

    @staticmethod
    def _apply_mask(entries: list[dict[str, Any]],
                    restrictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        masked_keys = {(item["source"], item["indicator"], item["period"]) for item in restrictions}
        result = []
        for entry in entries:
            if (entry["source"], entry["indicator"], entry["period"]) in masked_keys:
                masked = dict(entry)
                masked["value"] = MASKED_VALUE
                masked["unit"] = MASKED_UNIT
                result.append(masked)
            else:
                result.append(entry)
        return result

    def _manifest(self, batch: dict[str, Any], version: int,
                  entries: list[dict[str, Any]], prior: dict[str, Any] | None,
                  restrictions: list[dict[str, Any]]) -> dict[str, Any]:
        exported_entries = self._apply_mask(entries, restrictions)
        data_hash = sha256(canonical_bytes(exported_entries)).hexdigest()
        return {"schema_version": 1, "version": version, "parent_digest": prior["digest"] if prior else None,
                "batch": {"id": batch["id"], "source": batch["source"], "external_id": batch["external_id"],
                          "revision": batch["revision"], "payload_hash": batch["payload_hash"],
                          "row_count": batch["row_count"]},
                "entry_count": len(exported_entries), "entries_sha256": data_hash,
                "quality_findings": batch["findings"],
                "license_restrictions": restrictions}

    def publish(self, batch_id: int, expected_revision: int) -> dict[str, Any]:
        batch = self.store.batch(batch_id)
        if batch["published_version"]:
            if batch["revision"] != expected_revision:
                raise ContractError("stale_revision", "expected revision differs")
            return self.store.release(batch["published_version"])
        manifest = self.preview(batch_id, expected_revision)
        prior = self.store.latest_release()
        entries = self._entries(batch_id, prior["version"] if prior else None)
        # 每次发布都按当前许可重新评估全部条目（含继承自旧版本的条目）：
        # 重新授权只影响新发布；旧版本仍保留自己当时记录的限制，不被倒改。
        restrictions = self._restrictions(entries)
        exported_entries = self._apply_mask(entries, restrictions)
        digest = sha256(canonical_bytes(manifest)).hexdigest()
        return self.store.publish(batch_id, expected_revision, manifest, exported_entries,
                                  digest, restrictions)

    def export(self, version: int) -> dict[str, Any]:
        release = self.store.release(version)
        entries = self.store.release_entries(version)
        comparable = [{key: item[key] for key in ("source", "indicator", "period", "batch_id", "line", "value", "unit")}
                      for item in entries]
        actual = sha256(canonical_bytes(comparable)).hexdigest()
        if actual != release["manifest"]["entries_sha256"]:
            raise ContractError("release_corrupt", "release entries digest differs from manifest")
        manifest_digest = sha256(canonical_bytes(release["manifest"])).hexdigest()
        if manifest_digest != release["digest"]:
            raise ContractError("release_corrupt", "manifest digest differs from stored digest")
        if release["manifest"]["entry_count"] != len(entries):
            raise ContractError("release_corrupt", "release entry count differs")
        return {"manifest": release["manifest"], "digest": release["digest"], "entries": comparable}

    def export_with_current_license(self, version: int) -> dict[str, Any]:
        """按当前许可重新导出历史版本。

        已发布的原始快照（manifest/digest/entries）保持不变、仍可独立验证；本方法
        在其之外附加一层 overlay，只描述当前许可要求新增的遮蔽或停止，不重写历史。
        """
        bundle = self.export(version)
        if self.licensing is None:
            raise ContractError("license_unavailable", "license manager is not configured")
        overlay = []
        withheld = []
        for entry in bundle["entries"]:
            # 发布时已经遮蔽的条目不再重复处理。
            if entry["value"] is None:
                continue
            restriction = self.licensing.restriction_for(
                entry["source"], entry["indicator"], entry["period"])
            if restriction is None:
                continue
            decision = self._decision_for(entry["source"], restriction["notification_id"])
            item = {"source": entry["source"], "indicator": entry["indicator"],
                    "period": entry["period"], "mode": restriction["mode"],
                    "decision_id": decision["id"],
                    "notification_id": restriction["notification_id"],
                    "reason": restriction["reason"],
                    "effective_at": restriction["effective_at"],
                    "scope": restriction["scope"]}
            overlay.append(item)
            if restriction["mode"] == "stop":
                withheld.append(item)
        return {**bundle, "license_overlay": {
            "base_digest": bundle["digest"], "generated_for_version": version,
            "masked": [item for item in overlay if item["mode"] == "mask"],
            "withheld": withheld,
            "restriction_count": len(overlay)}}

    @staticmethod
    def verify(bundle: dict[str, Any]) -> bool:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("manifest"), dict):
            return False
        if not isinstance(bundle.get("entries"), list) or not isinstance(bundle.get("digest"), str):
            return False
        manifest = bundle["manifest"]
        if manifest.get("entry_count") != len(bundle["entries"]):
            return False
        try:
            entries_hash = sha256(canonical_bytes(bundle["entries"])).hexdigest()
            manifest_hash = sha256(canonical_bytes(manifest)).hexdigest()
        except (TypeError, ValueError):
            return False
        return entries_hash == manifest.get("entries_sha256") and manifest_hash == bundle["digest"]

    @staticmethod
    def verify_overlay(bundle: dict[str, Any]) -> bool:
        """校验覆盖层导出：基础快照仍须自洽，overlay 引用的条目必须真实存在。"""
        if not ReleaseBuilder.verify(bundle):
            return False
        overlay = bundle.get("license_overlay")
        if not isinstance(overlay, dict) or not isinstance(overlay.get("masked"), list) \
                or not isinstance(overlay.get("withheld"), list):
            return False
        entry_keys = {(item["source"], item["indicator"], item["period"])
                      for item in bundle["entries"]}
        for item in overlay["masked"] + overlay["withheld"]:
            if (item.get("source"), item.get("indicator"), item.get("period")) not in entry_keys:
                return False
        listed = len(overlay["masked"]) + len(overlay["withheld"])
        return overlay.get("restriction_count") == listed and overlay.get("base_digest") == bundle["digest"]

    def lineage(self, version: int) -> list[dict[str, Any]]:
        seen = set()
        result = []
        current = self.store.release(version)
        while current:
            if current["digest"] in seen:
                raise ContractError("release_cycle", "digest chain repeats")
            seen.add(current["digest"])
            result.append({"version": current["version"], "digest": current["digest"],
                           "batch": current["manifest"]["batch"]})
            if current["version"] == 1:
                break
            previous = self.store.release(current["version"] - 1)
            if current["manifest"]["parent_digest"] != previous["digest"]:
                raise ContractError("release_corrupt", "parent digest chain differs")
            current = previous
        return result
