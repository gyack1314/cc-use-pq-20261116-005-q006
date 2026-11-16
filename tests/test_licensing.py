from __future__ import annotations

import json

from climateledger.registry import ContractError
from support import LedgerCase


# 测试统一使用带偏移的 UTC 时间；生效时间是决策流排序的唯一依据。
T0 = "2026-03-01T00:00:00Z"
T1 = "2026-04-01T00:00:00Z"
T2 = "2026-05-01T00:00:00Z"
T3 = "2026-06-01T00:00:00Z"


class LicenseLifecycleTests(LedgerCase):
    def revoke(self, source="lab_a", *, notification_id="n1", action="revoke", mode="mask",
               indicator=None, period=None, reason="provider withdrew open release",
               effective_at=T1):
        decision = {"source": source, "action": action, "effective_at": effective_at,
                    "notification_id": notification_id, "reason": reason}
        if mode is not None:
            decision["mode"] = mode
        if indicator is not None:
            decision["indicator"] = indicator
        if period is not None:
            decision["period"] = period
        return self.service.record_license_decision(decision)

    def test_decision_requires_known_source_and_valid_shape(self):
        with self.assertRaisesRegex(ContractError, "unknown_source"):
            self.service.record_license_decision(
                {"source": "ghost", "action": "revoke", "effective_at": T1,
                 "notification_id": "x", "mode": "mask"})
        with self.assertRaisesRegex(ContractError, "license_action"):
            self.revoke(action="suspend", notification_id="bad")
        with self.assertRaisesRegex(ContractError, "license_mode"):
            self.revoke(mode="redact", notification_id="bad")
        with self.assertRaisesRegex(ContractError, "license_effective_at"):
            self.service.record_license_decision(
                {"source": "lab_a", "action": "revoke", "effective_at": "2026-04-01",
                 "notification_id": "x", "mode": "mask"})
        self.assertEqual(self.service.license_decisions(), [])

    def test_revoke_requires_mode_but_grant_rejects_it(self):
        with self.assertRaisesRegex(ContractError, "license_mode"):
            self.service.record_license_decision(
                {"source": "lab_a", "action": "revoke", "effective_at": T1,
                 "notification_id": "no-mode"})
        with self.assertRaisesRegex(ContractError, "license_mode"):
            self.revoke(action="grant", mode="mask", notification_id="g1")

    def test_period_scope_requires_indicator_and_matching_cadence(self):
        with self.assertRaisesRegex(ContractError, "license_scope"):
            self.revoke(period="2026-01", notification_id="p1")
        with self.assertRaisesRegex(ContractError, "period_format"):
            self.revoke(indicator="co2_ppm", period="2026", notification_id="p2")

    def test_replayed_notification_is_idempotent(self):
        first = self.revoke(notification_id="dup", reason="first wording")
        # 相同通知编号重放：即便 reason 文案不同，也不得产生新决策或新事件。
        second = self.revoke(notification_id="dup", reason="second wording")
        self.assertEqual(first, second)
        self.assertEqual(len(self.service.license_decisions("lab_a")), 1)
        events = [event for event in self.service.events("source:lab_a")
                  if event["kind"] == "license_revoke"]
        self.assertEqual(len(events), 1)

    def test_state_respects_effective_time_not_record_time(self):
        self.revoke(notification_id="future", effective_at=T2)
        before = self.service.license_state("lab_a", at=T1)
        self.assertEqual(before["scopes"], [])
        after = self.service.license_state("lab_a", at=T3)
        self.assertEqual(len(after["scopes"]), 1)
        self.assertEqual(after["scopes"][0]["action"], "revoke")

    def test_grant_restores_access_without_erasing_history(self):
        self.revoke(notification_id="r1", effective_at=T1)
        self.revoke(action="grant", mode=None, notification_id="g1", effective_at=T2)
        restricted = self.service.license_state("lab_a", at=T1)
        restored = self.service.license_state("lab_a", at=T3)
        self.assertEqual(restricted["scopes"][0]["action"], "revoke")
        self.assertEqual(restored["scopes"][0]["action"], "grant")
        # 决策流本身不可变，撤销记录仍然完整保留。
        actions = [row["action"] for row in self.service.license_decisions("lab_a")]
        self.assertEqual(actions, ["revoke", "grant"])

    def test_specific_scope_overrides_source_wide_scope(self):
        self.revoke(notification_id="wide", effective_at=T1)
        self.revoke(action="grant", mode=None, notification_id="narrow",
                    indicator="co2_ppm", period="2026-01", effective_at=T2)
        # 被精确重新授权的 (indicator, period) 不再受限。
        self.assertIsNone(self.service.licensing.restriction_for("lab_a", "co2_ppm", "2026-01", at=T3))
        # 同一来源的其他期间仍受来源级撤销约束。
        other = self.service.licensing.restriction_for("lab_a", "co2_ppm", "2026-02", at=T3)
        self.assertEqual(other["notification_id"], "wide")

    def test_ingest_snapshots_license_state_into_batch_metadata(self):
        self.revoke(notification_id="r1", effective_at=T0)
        batch, _ = self.ingest("after_revoke", self.rows(428, 429))
        snapshot = batch["metadata"]["license_snapshot"]
        self.assertEqual(snapshot["scopes"][0]["notification_id"], "r1")
        # 撤权不阻断内部留痕：批次与测量仍然完整保存，来源可追溯。
        self.assertEqual(len(self.service.batch(batch["id"])["measurements"]), 2)

    def test_mask_restriction_shadows_values_on_publish(self):
        self.revoke(notification_id="r1", mode="mask", effective_at=T0)
        batch, _ = self.ingest("masked", self.rows(428, 429))
        release = self.service.publish(batch["id"], batch["revision"])
        bundle = self.service.export(release["version"])
        self.assertTrue(all(entry["value"] is None for entry in bundle["entries"]))
        self.assertTrue(all(entry["unit"] == "restricted" for entry in bundle["entries"]))
        # 清单明确说明被限制的范围，且快照仍可独立校验。
        restrictions = bundle["manifest"]["license_restrictions"]
        self.assertEqual({item["mode"] for item in restrictions}, {"mask"})
        self.assertEqual(len(restrictions), 2)
        self.assertTrue(self.service.verify(bundle))
        stored = self.service.release_restrictions(release["version"])
        self.assertEqual({row["period"] for row in stored}, {"2026-01", "2026-02"})

    def test_stop_restriction_blocks_approval_and_publish(self):
        self.revoke(notification_id="stop1", mode="stop", effective_at=T0)
        batch, _ = self.ingest("stopped", self.rows(428, 429))
        with self.assertRaisesRegex(ContractError, "license_withheld"):
            self.service.approve(batch["id"], batch["revision"])
        with self.assertRaisesRegex(ContractError, "license_withheld"):
            self.service.publish(batch["id"], batch["revision"])
        self.assertIsNone(self.service.status()["latest_release"])

    def test_stop_on_one_period_blocks_only_while_other_scope_can_mask(self):
        self.revoke(notification_id="m1", mode="mask", indicator="co2_ppm",
                    period="2026-01", effective_at=T0)
        self.revoke(notification_id="s1", mode="stop", indicator="co2_ppm",
                    period="2026-02", effective_at=T0)
        batch, _ = self.ingest("mixed", self.rows(428, 429))
        with self.assertRaisesRegex(ContractError, "license_withheld"):
            self.service.publish(batch["id"], batch["revision"])
        result = self.service.ingest(self.manifest("mixed_followup", self.rows(428, 429)))
        self.assertEqual({row["period"] for row in result["license_withheld"]}, {"2026-02"})

    def test_historical_snapshot_stays_verifiable_after_later_revocation(self):
        batch, release, _ = self.release()
        original = self.service.export(release["version"])
        self.revoke(notification_id="later", mode="mask", effective_at=T2)
        # 旧版本导出逐字节不变，仍可验证。
        self.assertEqual(self.service.export(release["version"]), original)
        self.assertTrue(self.service.verify(original))
        # 按当前许可再导出：overlay 标出新增限制，但不重写基础快照。
        overlay_bundle = self.service.export_with_current_license(release["version"])
        self.assertEqual(overlay_bundle["digest"], original["digest"])
        self.assertEqual(overlay_bundle["license_overlay"]["restriction_count"], 2)
        self.assertTrue(self.service.verify(overlay_bundle))
        self.assertTrue(self.service.releases.verify_overlay(overlay_bundle))

    def test_overlay_reports_withheld_for_stop_mode(self):
        batch, release, _ = self.release()
        self.revoke(notification_id="stop-later", mode="stop", effective_at=T2)
        overlay_bundle = self.service.export_with_current_license(release["version"])
        self.assertEqual(len(overlay_bundle["license_overlay"]["withheld"]), 2)
        self.assertEqual(overlay_bundle["license_overlay"]["masked"], [])

    def test_regrant_restores_value_in_new_release_but_old_snapshot_keeps_mask(self):
        self.revoke(notification_id="rv", mode="mask", effective_at=T0)
        first_batch, _ = self.ingest("early", self.rows(428))
        first = self.service.publish(first_batch["id"], first_batch["revision"])
        self.assertIsNone(self.service.export(first["version"])["entries"][0]["value"])
        # 重新授权后发布新版本：旧出处恢复真实值，旧版本快照维持遮蔽。
        self.revoke(action="grant", mode=None, notification_id="gr", effective_at=T2)
        next_batch, _ = self.ingest("later", self.rows(430, start=2))
        second = self.service.publish(next_batch["id"], next_batch["revision"])
        entries = {entry["period"]: entry["value"]
                   for entry in self.service.export(second["version"])["entries"]}
        self.assertEqual(entries["2026-01"], "428.00")
        self.assertEqual(entries["2026-02"], "430.00")
        self.assertIsNone(self.service.export(first["version"])["entries"][0]["value"])
        self.assertEqual(len(self.service.release_restrictions(first["version"])), 1)
        self.assertEqual(self.service.release_restrictions(second["version"]), [])
        # 两个版本的审计都应当通过：遮蔽与解遮蔽都能被正确解释。
        self.assertEqual(self.service.audit_all()["violations"], [])

    def test_regrant_does_not_retroactively_change_old_decisions(self):
        self.revoke(notification_id="r1", mode="mask", effective_at=T1)
        batch, _ = self.ingest("window", self.rows(428))
        first = self.service.publish(batch["id"], batch["revision"])
        first_bundle = self.service.export(first["version"])
        self.assertIsNone(first_bundle["entries"][0]["value"])
        # 之后重新授权，只影响之后的新发布。
        self.revoke(action="grant", mode=None, notification_id="g1", effective_at=T2)
        second_batch, _ = self.ingest("window2", self.rows(429, start=2))
        second = self.service.publish(second_batch["id"], second_batch["revision"])
        second_bundle = self.service.export(second["version"])
        # 旧版本维持遮蔽；新版本中的新观测正常导出，历史决策未被倒改。
        self.assertIsNone(first_bundle["entries"][0]["value"])
        self.assertEqual(
            [entry for entry in second_bundle["entries"] if entry["period"] == "2026-02"][0]["value"],
            "429.00")
        prior_restrictions = self.service.release_restrictions(first["version"])
        self.assertEqual(len(prior_restrictions), 1)

    def test_publish_manifest_records_restriction_scope_and_notification(self):
        self.revoke(notification_id="scoped", mode="mask", indicator="co2_ppm",
                    period="2026-01", effective_at=T0)
        batch, _ = self.ingest("scoped", self.rows(428, 429))
        release = self.service.publish(batch["id"], batch["revision"])
        manifest = self.service.export(release["version"])["manifest"]
        restrictions = manifest["license_restrictions"]
        self.assertEqual(len(restrictions), 1)
        self.assertEqual(restrictions[0]["period"], "2026-01")
        self.assertEqual(restrictions[0]["notification_id"], "scoped")
        self.assertEqual(restrictions[0]["scope"], {"indicator": "co2_ppm", "period": "2026-01"})

    def test_audit_trail_captures_license_events(self):
        self.revoke(notification_id="r1", effective_at=T1)
        self.revoke(action="grant", mode=None, notification_id="g1", effective_at=T2)
        kinds = [event["kind"] for event in self.service.events("source:lab_a")]
        self.assertEqual(kinds, ["license_revoke", "license_grant"])

    def test_audit_distinguishes_license_masking_from_corruption(self):
        self.revoke(notification_id="r1", mode="mask", effective_at=T0)
        batch, _ = self.ingest("audited", self.rows(428, 429))
        release = self.service.publish(batch["id"], batch["revision"])
        trace = self.service.audit.release_trace(release["version"])
        self.assertTrue(trace["verified"])
        self.assertEqual(trace["masked_count"], 2)
        self.assertEqual(trace["broken_entries"], [])
        report = self.service.audit_all()
        self.assertEqual(report["violations"], [])
        self.assertEqual(report["license_audit"]["restriction_total"], 2)

    def test_audit_detects_restriction_table_tampering(self):
        self.revoke(notification_id="r1", mode="mask", effective_at=T0)
        batch, _ = self.ingest("tampered", self.rows(428, 429))
        release = self.service.publish(batch["id"], batch["revision"])
        self.service.store.connection.execute(
            "DELETE FROM release_restrictions WHERE version=?", (release["version"],))
        trace = self.service.audit.release_trace(release["version"])
        self.assertFalse(trace["verified"])
        reasons = {item["reason"] for item in trace["broken_entries"]}
        self.assertIn("unrecorded_mask", reasons)
        self.assertIn("restriction_table_mismatch", reasons)

    def test_specific_scope_beats_newer_source_wide_decision(self):
        # 旧的精确撤销 + 新的来源级重新授权：精确作用域仍应保持受限。
        self.revoke(notification_id="exact", mode="mask", indicator="co2_ppm",
                    period="2026-01", effective_at=T1)
        self.revoke(action="grant", mode=None, notification_id="wide_grant", effective_at=T2)
        restriction = self.service.licensing.restriction_for("lab_a", "co2_ppm", "2026-01", at=T3)
        self.assertIsNotNone(restriction)
        self.assertEqual(restriction["notification_id"], "exact")
        # 未被精确作用域覆盖的其他期间，跟随来源级 grant 恢复。
        self.assertIsNone(self.service.licensing.restriction_for("lab_a", "co2_ppm", "2026-02", at=T3))

    def test_license_state_for_other_source_is_independent(self):
        self.revoke(source="lab_a", notification_id="r1", effective_at=T0)
        state_b = self.service.license_state("lab_b")
        self.assertEqual(state_b["scopes"], [])
        self.assertIsNone(self.service.licensing.restriction_for("lab_b", "co2_ppm", "2026-01"))


class LicenseCliTests(LedgerCase):
    def write_decision(self, name, decision):
        path = self.root / name
        path.write_text(json.dumps(decision), encoding="utf-8")
        return str(path)

    def test_cli_license_flow_and_masked_export(self):
        from climateledger.cli import main
        from io import StringIO
        from contextlib import redirect_stdout, redirect_stderr

        def call(*args):
            out, err = StringIO(), StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["--db", str(self.db), *args])
            return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

        # 先在许可有效时发布一个正常快照。
        manifest = self.manifest("cli_batch", self.rows(428))
        call("ingest", str(manifest))
        batch_id = call("batches")[1][0]["id"]
        code, published, _ = call("publish", str(batch_id), "1")
        self.assertEqual(code, 0)
        self.assertEqual(call("restrictions", str(published["version"]))[1], [])

        # 之后收到撤权通知（生效时间晚于发布），历史快照本身保持可验证。
        decision = self.write_decision("revoke.json", {
            "source": "lab_a", "action": "revoke", "mode": "mask",
            "effective_at": T2, "notification_id": "cli-1", "reason": "CLI flow"})
        self.assertEqual(call("record-license", decision)[0], 0)
        code, state, _ = call("license-state", "lab_a", "--at", T0)
        self.assertEqual(code, 0)
        self.assertEqual(state["scopes"], [])
        code, state, _ = call("license-state", "lab_a", "--at", T3)
        self.assertEqual(state["scopes"][0]["notification_id"], "cli-1")
        self.assertEqual(len(call("license-decisions")[1]), 1)
        # 重放同一通知文件：不新增决策。
        self.assertEqual(call("record-license", decision)[0], 0)
        self.assertEqual(len(call("license-decisions")[1]), 1)

        # 按当前许可再导出：overlay 标出新增遮蔽，基础快照不变。
        out_path = self.root / "licensed.json"
        code, exported, _ = call("export-licensed", "1", "--output", str(out_path))
        self.assertEqual(code, 0)
        self.assertEqual(exported["restriction_count"], 1)
        code, verified, _ = call("verify", str(out_path))
        self.assertEqual(code, 0)
        self.assertTrue(verified["verified"])
