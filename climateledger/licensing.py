"""来源授权决策的生命周期。

授权以不可变决策流的方式记录：每条决策（撤销 revoke / 重新授权 grant）带有生效
时间、通知编号和作用域。决策本身永不修改，当前许可状态由截至某时刻的决策流计算
得出，因此重新授权无法倒改历史发布时已经做出的限制决定。
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from .normalize import normalize_period
from .registry import ContractError, Registry, identifier
from .store import utc_now


ACTIONS = ("revoke", "grant")
MODES = ("mask", "stop")


def parse_effective_at(value: Any) -> str:
    """校验生效时间，统一为秒精度 UTC ISO-8601 文本，便于与决策流比较。"""
    if not isinstance(value, str) or not value.strip():
        raise ContractError("license_effective_at", "effective_at must be nonempty ISO-8601 text")
    text = value.strip()
    try:
        if text.endswith(("Z", "z")):
            parsed = datetime.fromisoformat(text[:-1] + "+00:00")
        else:
            parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ContractError("license_effective_at", f"effective_at {value!r} is not valid ISO-8601") from None
    if parsed.tzinfo is None:
        raise ContractError("license_effective_at", "effective_at must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class LicenseDecision:
    id: int
    source: str
    action: str
    effective_at: str
    notification_id: str
    reason: str
    indicator: str | None
    period: str | None
    mode: str | None
    recorded_at: str

    @classmethod
    def from_input(cls, value: dict[str, Any], registry: Registry) -> "LicenseDecision":
        if not isinstance(value, dict):
            raise ContractError("license_shape", "license decision must be an object")
        source = identifier(value.get("source"), "source")
        # 来源必须已注册，决策才有归属。
        registry.source(source)
        action = value.get("action")
        if action not in ACTIONS:
            raise ContractError("license_action", "action must be revoke or grant")
        effective_at = parse_effective_at(value.get("effective_at"))
        notification_id = value.get("notification_id")
        if not isinstance(notification_id, str) or not 1 <= len(notification_id.strip()) <= 120:
            raise ContractError("license_notification", "notification_id must contain 1-120 characters")
        notification_id = notification_id.strip()
        reason = value.get("reason", "")
        if not isinstance(reason, str) or len(reason) > 400:
            raise ContractError("license_reason", "reason must be text of at most 400 characters")
        indicator = value.get("indicator")
        if indicator is not None:
            indicator = identifier(indicator, "indicator")
            registered = registry.indicator(indicator)
        period = value.get("period")
        if period is not None:
            if indicator is None:
                raise ContractError("license_scope", "period scope requires an indicator")
            if not isinstance(period, str):
                raise ContractError("license_scope", "period must be text")
            # 复用周期格式校验，确保作用域键与测量周期写法一致。
            normalize_period(period, registered.cadence)
        mode = value.get("mode")
        if action == "revoke":
            if mode not in MODES:
                raise ContractError("license_mode", "revoke requires mode mask or stop")
        elif mode is not None:
            raise ContractError("license_mode", "grant decisions cannot carry a mode")
        return cls(0, source, action, effective_at, notification_id, reason.strip(),
                   indicator, period, mode, "")

    def document(self) -> dict[str, Any]:
        return asdict(self)


class LicenseManager:
    """在不可变决策流之上计算许可状态与逐条出处限制。"""

    def __init__(self, store, registry: Registry):
        self.store = store
        self.registry = registry

    def record(self, value: dict[str, Any]) -> dict[str, Any]:
        decision = LicenseDecision.from_input(value, self.registry)
        stored = self.store.record_license_decision(decision)
        return stored

    def decisions(self, source: str | None = None) -> list[dict[str, Any]]:
        return self.store.list_license_decisions(source)

    def state_at(self, source: str, at: str | None = None) -> dict[str, Any]:
        """截至 at（默认当前时刻）来源的有效许可状态，按作用域特异性排列。"""
        self.registry.source(source)
        moment = utc_now() if at is None else parse_effective_at(at)
        rows = [row for row in self.store.list_license_decisions(source)
                if row["effective_at"] <= moment]
        # 每个作用域键只保留该作用域上最近一条决策；不同特异性的作用域各自独立。
        effective: dict[tuple[str | None, str | None], dict[str, Any]] = {}
        for row in sorted(rows, key=lambda item: (item["effective_at"], item["id"])):
            effective[(row["indicator"], row["period"])] = row
        scopes = []
        for (indicator, period), row in sorted(
                effective.items(), key=lambda kv: (kv[0][0] is None, kv[0][0] or "",
                                                    kv[0][1] is None, kv[0][1] or "")):
            scopes.append({"indicator": indicator, "period": period, "action": row["action"],
                           "mode": row["mode"], "effective_at": row["effective_at"],
                           "notification_id": row["notification_id"], "reason": row["reason"]})
        return {"source": source, "at": moment, "scopes": scopes}

    def snapshot(self, source: str, at: str | None = None) -> dict[str, Any]:
        """摄入时附在批次元数据上的许可快照。"""
        state = self.state_at(source, at)
        return {"at": state["at"], "decision_count": len(self.decisions(source)),
                "scopes": state["scopes"]}

    @staticmethod
    def _specificity(row: dict[str, Any]) -> int:
        # 特异性：精确到（指标、期间）= 2，仅指标 = 1，来源级 = 0。
        if row["indicator"] is not None and row["period"] is not None:
            return 2
        if row["indicator"] is not None:
            return 1
        return 0

    def _effective_decision(self, source: str, indicator: str, period: str,
                            at: str) -> dict[str, Any] | None:
        """取有效决策：先比作用域特异性，同一特异性上再取最新一条。"""
        rows = [row for row in self.store.list_license_decisions(source)
                if row["effective_at"] <= at
                and (row["indicator"] is None or row["indicator"] == indicator)
                and (row["period"] is None or row["period"] == period)]
        best: dict[str, Any] | None = None
        for row in rows:
            rank = (self._specificity(row), row["effective_at"], row["id"])
            if best is None or rank > (self._specificity(best), best["effective_at"], best["id"]):
                best = row
        return best

    def restriction_for(self, source: str, indicator: str, period: str,
                        at: str | None = None) -> dict[str, Any] | None:
        """按最具体作用域返回当前生效的撤销限制，无限制（含已重新授权）返回 None。"""
        self.registry.source(source)
        moment = utc_now() if at is None else parse_effective_at(at)
        row = self._effective_decision(source, indicator, period, moment)
        if row is None or row["action"] != "revoke":
            return None
        return {"mode": row["mode"], "reason": row["reason"],
                "effective_at": row["effective_at"],
                "notification_id": row["notification_id"],
                "scope": {"indicator": row["indicator"], "period": row["period"]}}

    def blocks_approval(self, source: str, measurements: list[dict[str, Any]],
                        at: str | None = None) -> list[dict[str, Any]]:
        """stop 作用域命中的测量不允许进入审核/发布流程。"""
        blocked = []
        for item in measurements:
            restriction = self.restriction_for(source, item["indicator"], item["period"], at)
            if restriction is not None and restriction["mode"] == "stop":
                blocked.append({"indicator": item["indicator"], "period": item["period"], **restriction})
        return blocked
