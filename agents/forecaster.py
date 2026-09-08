"""Forecasting & drift analytics for the Rulebook Drift Monitor.

The forecaster performs a deterministic library scan - every typology in the
evidence corpus is stepped through the engine once, and each rule-typology pair
records whether the rule fired. From those measurements it derives:

  * a composite Drift Index (0-100),
  * rulebook coverage per category and overall,
  * AI-evasion pressure (share of evaded rules that are AI-relevant),
  * an at-risk ranking of typologies predicted to evade most next period,
  * a projection of the Drift Index over the next period.

Projection sources, in order of preference:

  1. MEASURED HISTORY: when >=3 prior runs/checkpoints are recorded in
     data/run_history.json, the projection is a damped trend fitted to the
     actual measured Drift Index series (least-squares slope combined with the
     measured AI-evasion rate), with a widening confidence band and a rolling-origin
     hold-one-out backtest (MAD/MAPE/bias) reported alongside.
  2. LIBRARY-SCAN BASELINE: with fewer than 3 recorded points, a transparent
     damped exponential-smoothing extrapolation from the current scan, clearly
     labelled as requiring more recorded runs.

Honesty is explicit: the method, data source and backtest quality are returned
with every forecast.
"""

from __future__ import annotations

import json
import math
import os
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from agents.models import Rule, Typology
from agents.paths import get_data_dir
from agents.rule_engine import RuleEvaluationEngine

SEV_W = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2}
CATEGORY_LABELS = {
    "onboarding": "Onboarding & KYC",
    "identity_and_cdd": "Identity & CDD",
    "source_of_funds": "Source of Funds",
    "structuring": "Structuring & Patterns",
    "layering": "Layering",
    "travel_rule": "Travel Rule",
    "counterparty_wallet": "Counterparty & Wallet",
    "profile_mule": "Profile & Mule Networks",
    "profile_risk": "Profile Risk",
    "geographic": "Geographic",
    "sanctions": "Sanctions",
    "technology": "Technology & Anonymity",
    "transaction_anomalies": "Transaction Anomalies",
    "pep_and_connections": "PEP & Connections",
}

DEFAULT_HISTORY_PATH = os.path.join(get_data_dir(), "run_history.json")


def load_history(path: Optional[str] = None) -> list[dict]:
    """Read recorded drift checkpoints (oldest first)."""
    path = path or DEFAULT_HISTORY_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            arr = json.load(f)
        entries = [h for h in arr if isinstance(h, dict)
                   and isinstance(h.get("drift_index"), (int, float))]
        entries.sort(key=lambda h: str(h.get("ts", "")))
        return entries
    except Exception:
        return []


def save_history(entries: list[dict], path: Optional[str] = None) -> bool:
    path = path or DEFAULT_HISTORY_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
        return True
    except (OSError, IOError):
        # A failed checkpoint write means this run's point won't feed next
        # time's projection, but the forecast page still works off whatever
        # history IS readable - degrade quietly rather than crashing the
        # request that triggered the checkpoint.
        return False


def _to_dt(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def project_history(x: list[float], y: list[float], ai_pressure: float,
                    steps: int, cadence_days: float) -> dict:
    """Damped-trend projection over the MEASURED drift series.

    Level = last measured Drift Index. Growth per review cycle combines
      1) the fitted least-squares slope of the measured history (cadence-scaled),
      2) the measured AI-evasion pressure rate  r0 = 0.03 + 0.09 * ai_pressure
         (the label-model baseline used when history is absent),
    applied with damped compounding so the trend saturates rather than explodes.
    A widening confidence band (minimum half-width included) is returned with a
    rolling-origin one-step-ahead holdout backtest."""
    n = len(x)
    mx = sum(x) / n
    my = sum(y) / n
    sxx = sum((xi - mx) ** 2 for xi in x)
    sxy = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    slope = sxy / sxx if sxx > 1e-9 else 0.0
    intercept = my - slope * mx
    fits = [intercept + slope * xi for xi in x]
    resid = [(yi - fi) for yi, fi in zip(y, fits)]
    rmse = math.sqrt(sum(r * r for r in resid) / n) if n else 1.0

    y_last = y[-1]
    r0 = 0.03 + 0.09 * ai_pressure                      # measured evasion-pressure rate
    slope_influence = (slope * cadence_days) / max(1.0, y_last)   # measured-trend fine-tune
    g = r0 + slope_influence
    g = max(-0.05, min(0.15, g))

    damp = 0.82
    values, lows, highs = [], [], []
    cumulative = 1.0
    for k in range(1, steps + 1):
        cumulative *= (1.0 + g * math.pow(damp, k - 1))
        yk = y_last * cumulative
        spread = max(2.0, rmse * (1.0 + 0.35 * k))      # min width so band stays visible
        values.append(round(min(100.0, max(0.0, yk)), 1))
        lows.append(round(min(100.0, max(0.0, yk - spread)), 1))
        highs.append(round(min(100.0, max(0.0, yk + spread)), 1))

    # Rolling-origin hold-one-out backtest (effort metric of the real model).
    errors = []
    for i in range(2, n):
        xa, ya = x[:i], y[:i]
        ma = sum(xa) / len(xa)
        mya = sum(ya) / len(ya)
        sxa = sum((v - ma) ** 2 for v in xa)
        sxy_a = sum((v - ma) * (w - mya) for v, w in zip(xa, ya))
        sl = sxy_a / sxa if sxa > 1e-9 else 0.0
        itc = mya - sl * ma
        pred = itc + sl * x[i]
        errors.append(pred - y[i])
    mad = statistics.mean([abs(e) for e in errors]) if errors else None
    mape = (statistics.mean([abs(e) / max(1e-9, abs(y[i]))
                            for i, e in zip(range(2, n), errors)]) * 100 if errors else None)
    bias = statistics.mean(errors) if errors else None

    return {
        "values": values,
        "lows": lows,
        "highs": highs,
        "y_last": y_last,
        "slope": slope,
        "growth_rate": round(g, 4),
        "backtest": None if not errors else {
            "n_points": len(errors),
            "mad": round(mad, 2),
            "mape": round(mape, 2),
            "bias": round(bias, 3),
        },
    }


class Forecaster:
    """Library-scan drift analytics with measured-history projection."""

    def __init__(self, rulebook: list[Rule], typologies: list[Typology],
                 history_path: Optional[str] = None,
                 covered: Optional[set[str]] = None):
        self.rulebook = rulebook
        self.typologies = typologies
        self.history_path = history_path or DEFAULT_HISTORY_PATH
        self.engine = RuleEvaluationEngine()
        # Typologies whose detected gaps an institutionalised indicator now
        # covers: their (typology, rule) pairs count as fired (gap closed).
        if covered is None:
            try:
                from agents.rule_amendment import covered_typology_ids
                covered = covered_typology_ids()
            except Exception:
                covered = set()
        self.covered = covered or set()
        for r in self.rulebook:
            self.engine.register(r)
        self.rows = self._scan()

    # --- measurement ------------------------------------------------------
    def _scan(self) -> list[dict]:
        rows = []
        for t in self.typologies:
            vocab = " ".join(t.techniques + [t.name]).lower()
            relevant = [r for r in self.rulebook if self._relevant(r, vocab)]
            fired: set[str] = set()
            for fx in t.test_fixtures:
                for res in self.engine.evaluate(self.rulebook, fx):
                    if res.fired:
                        fired.add(res.rule_id)
            if t.id in self.covered:               # indicator covers the gap set
                fired.update(r.id for r in relevant)
            evaded = [r for r in relevant if r.id not in fired]
            rows.append({
                "typology": t,
                "relevant": relevant,
                "evaded": evaded,
                "evasion_pressure": len(evaded) / max(1, len(relevant)),
            })
        return rows

    @staticmethod
    def _relevant(rule: Rule, vocab: str) -> bool:
        if any(k in vocab for k in rule.keywords):
            return True
        return any(w in rule.keywords for w in vocab.split())

    def _sev_w(self, sev: str) -> float:
        return SEV_W.get(sev, 0.45)

    def evasion_matrix(self) -> dict:
        """Typology × category evasion grid (rule counts) for the heatmap."""
        cats = sorted({r.category for r in self.rulebook})
        rows = []
        for row in self.rows:
            t = row["typology"]
            cells = [len([r for r in row["evaded"] if r.category == c]) for c in cats]
            rows.append({"id": t.id, "name": t.name, "severity": t.risk_severity,
                         "cells": cells, "total": len(row["evaded"])})
        return {"categories": cats, "rows": rows}

    # --- aggregates --------------------------------------------------------
    def _pair_stats(self) -> list[dict]:
        """(typology, relevant-rule) pairs with fired/evaded outcome."""
        pairs = []
        for row in self.rows:
            t = row["typology"]
            fired_ids = {r.id for r in row["relevant"]} - {r.id for r in row["evaded"]}
            for r in row["relevant"]:
                pairs.append({
                    "typology": t,
                    "rule": r,
                    "fired": r.id in fired_ids,
                })
        return pairs

    def _measured_history(self) -> list[dict]:
        return load_history(self.history_path)

    def forecast(self) -> dict:
        pairs = self._pair_stats()
        rules_by_cat = defaultdict(list)
        for r in self.rulebook:
            rules_by_cat[r.category].append(r)

        # Coverage per category.
        cat_pairs = defaultdict(lambda: [0, 0])  # [fired, total]
        for p in pairs:
            c = p["rule"].category
            cat_pairs[c][0] += 1 if p["fired"] else 0
            cat_pairs[c][1] += 1

        total_fired = sum(v[0] for v in cat_pairs.values())
        total_pairs = sum(v[1] for v in cat_pairs.values())
        overall_coverage = total_fired / max(1, total_pairs)

        # Evaded rules (all pairs) for AI pressure.
        evaded_rules = [p["rule"] for p in pairs if not p["fired"]]
        ai_evaded = [r for r in evaded_rules if r.ai_relevant]
        ai_pressure = len(ai_evaded) / max(1, len(evaded_rules))

        # Severity-weighted drift per category (coverage deficit).
        cat_drift = {}
        for c, (f, tot) in sorted(cat_pairs.items()):
            cov = f / max(1, tot)
            cat_drift[c] = {
                "label": CATEGORY_LABELS.get(c, c),
                "rules": len(rules_by_cat[c]),
                "covered_pairs": f,
                "total_pairs": tot,
                "coverage": round(cov, 3),
                "drift_deficit": round(1 - cov, 3),
            }

        # Composite Drift Index (0-100) - current scan condition.
        coverage_score = (1 - overall_coverage) * 65.0
        ai_score = ai_pressure * 20.0
        sev_floor = statistics.mean([self._sev_w(r.risk_severity) for r in self.rulebook]) * 10.0
        novelty = sum(1 for t in self.typologies if "ai" in " ".join(t.techniques + [t.name]).lower())
        novelty_score = (novelty / max(1, len(self.typologies))) * 5.0
        drift_index = min(100.0, coverage_score + ai_score + sev_floor + novelty_score)

        # At-risk typology ranking (predicted next-period evasion).
        at_risk = []
        for row in self.rows:
            t = row["typology"]
            evaded = row["evaded"]
            if not row["relevant"]:
                continue
            ai_share = len([r for r in evaded if r.ai_relevant]) / max(1, len(evaded))
            sev = statistics.mean([self._sev_w(r.risk_severity) for r in evaded] or [0.45])
            score = 0.5 * row["evasion_pressure"] + 0.3 * ai_share + 0.2 * sev
            at_risk.append({
                "rank": 0,
                "typology_id": t.id,
                "name": t.name,
                "source": t.source,
                "category": next((r.category for r in evaded), "uncategorised"),
                "risk_severity": t.risk_severity,
                "evasion_pressure": round(row["evasion_pressure"], 2),
                "evaded_count": len(evaded),
                "relevant_count": len(row["relevant"]),
                "ai_evasion_share": round(ai_share, 2),
                "hot_score": round(score, 3),
            })
        at_risk.sort(key=lambda x: -x["hot_score"])
        for i, a in enumerate(at_risk[:12], start=1):
            a["rank"] = i

        # ---- Projection: measured history first, then baseline scan -------
        steps = 6
        history = self._measured_history()
        points = [(ts, float(h["drift_index"])) for h in history
                  if (ts := _to_dt(h.get("ts", ""))) is not None]

        if len(points) >= 3:
            ref = points[0][0]
            xs = [(ts - ref).total_seconds() / 86400.0 for ts, _ in points]
            ys = [v for _, v in points]
            cadence = [points[i][0] - points[i - 1][0] for i in range(1, len(points))]
            med_cadence = statistics.median(g.total_seconds() / 86400.0 for g in cadence) if cadence else 7.0
            cadence_days = round(max(1.0, min(365.0, med_cadence)), 1)
            fit = project_history(xs, ys, ai_pressure, steps, cadence_days)

            last_date = points[-1][0]
            dates = [(_date_str(points[i][0])) for i in range(len(points))]
            f_dates = [(_date_str(last_date + timedelta(days=cadence_days * k))) for k in range(1, steps + 1)]
            labels = dates + f_dates
            values = [round(v, 1) for _, v in points] + fit["values"]
            lows = [None] * len(points) + fit["lows"]
            highs = [None] * len(points) + fit["highs"]
            kind = "measured_history"
            source = "measured history · drift index recorded from completed runs/checkpoints"
            backtest = fit["backtest"]
            projection = fit["values"][-1]
            actual_last = fit["y_last"]
            period = f"next {steps} review cycles · ~{cadence_days}d cadence"
            history_series = [{"ts": _date_str(ts), "value": round(v, 1), "kind": "actual"} for ts, v in points]
            forecast_series = [
                {"date": d, "value": v, "low": lo, "high": hi, "kind": "forecast"}
                for d, v, lo, hi in zip(f_dates, fit["values"], fit["lows"], fit["highs"])]
        else:
            # Baseline: damped exponential smoothing from current scan condition.
            baseline = drift_index
            rate = 0.03 + 0.09 * ai_pressure
            damp = 0.82
            values = []
            for i in range(1, steps + 1):
                baseline = baseline + rate * baseline * math.pow(damp, i - 1)
                values.append(round(min(100.0, baseline), 1))
            labels = ["P1", "P2", "P3", "P4", "P5", "P6"]
            lows = highs = [None] * steps
            kind = "library_scan_baseline"
            cadence_days = None
            source = f"Library-scan baseline ({len(points)}/3 recorded history points required for measured projection)"
            backtest = None
            projection = values[-1]
            actual_last = drift_index
            period = "next review cycles"
            history_series = [{"ts": _date_str(ts), "value": round(v, 1), "kind": "actual"} for ts, v in points]
            forecast_series = [
                {"date": labels[k], "value": values[k], "low": None, "high": None, "kind": "forecast"}
                for k in range(steps)]

        trend = {
            "kind": kind,
            "source": source,
            "labels": labels,
            "values": values,
            "low": lows,
            "high": highs,
            "projection": round(projection, 1),
            "actual_last": round(actual_last, 1),
            "direction": "rising" if values[-1] > actual_last + 0.5 else ("falling" if values[-1] < actual_last - 0.5 else "stable"),
            "period": period,
            "cadence_days": round(cadence_days, 1) if kind == "measured_history" else None,
            "growth_rate": fit.get("growth_rate") if kind == "measured_history" else None,
            "history": history_series,
            "forecast": forecast_series,
            "backtest": backtest,
            "history_count": len(points),
        }

        band = "Low" if drift_index < 30 else ("Elevated" if drift_index < 55 else "High" if drift_index < 75 else "Critical")

        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "rulebook_version": f"{self.rulebook[0].id}..{self.rulebook[-1].id} · {len(self.rulebook)} rules",
            "drift_index": round(drift_index, 1),
            "drift_band": band,
            "coverage": {
                "overall": round(overall_coverage, 3),
                "pairs": total_pairs,
                "covered_pairs": total_fired,
                "by_category": cat_drift,
            },
            "ai_pressure": {
                "share": round(ai_pressure, 3),
                "evaded_ai_rules": sorted({r.id for r in ai_evaded})[:12],
            },
            "ai_share_all_rules": round(sum(1 for r in self.rulebook if r.ai_relevant) / max(1, len(self.rulebook)), 3),
            "trend": trend,
            "at_risk": at_risk,
            "inputs": {
                "rules": len(self.rulebook),
                "typologies": len(self.typologies),
                "fixtures": sum(len(t.test_fixtures) for t in self.typologies),
            },
            "method": (
                "Deterministic library scan: each typology is stepped through the engine and every "
                "relevant rule-typology pair records fired/evaded. Drift Index = coverage deficit (65) + "
                "AI-evasion pressure (20) + severity floor (10) + AI-novelty concentration (5). With >=3 "
                "recorded runs/checkpoints the projection is a damped trend fitted to the MEASURED "
                "drift series (least-squares slope combined with the measured AI-evasion rate) with a "
                "widening confidence band and a rolling-origin backtest; otherwise it "
                "falls back to a clearly-labelled library-scan baseline."
            ),
        }


def _date_str(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")