import copy
from collections import Counter
import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from config import config
from src.sqlite_store import SQLiteAlertRepository

try:
    import fcntl
except ImportError:  # Windows host fallback; production runs in Linux containers.
    fcntl = None


logger = logging.getLogger(__name__)
_json_lock = threading.Lock()
_dual_lock = threading.Lock()


class JsonAlertRepository:
    @property
    def path(self):
        return config.OUTPUT_ALERT_FILE

    @contextmanager
    def _locked(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with _json_lock, open(self.path + ".lock", "a", encoding="utf-8") as lock_file:
            if fcntl:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _read_lines(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()

    @staticmethod
    def _same_alert(left, right):
        if left.get("alert_id") and right.get("alert_id"):
            return left["alert_id"] == right["alert_id"]
        return (
            left.get("timestamp") == right.get("timestamp")
            and left.get("alert_name") == right.get("alert_name")
            and left.get("raw_log") == right.get("raw_log")
        )

    def create_alert(self, alert: dict) -> dict:
        with self._locked():
            lines = self._read_lines()
            replaced = False
            with open(self.path, "w", encoding="utf-8") as file:
                for line in lines:
                    try:
                        existing = json.loads(line)
                    except json.JSONDecodeError:
                        file.write(line)
                        continue
                    if not replaced and self._same_alert(existing, alert):
                        file.write(json.dumps(alert, ensure_ascii=False) + "\n")
                        replaced = True
                    else:
                        file.write(line)
                if not replaced:
                    file.write(json.dumps(alert, ensure_ascii=False) + "\n")
        return alert

    def update_alert(self, alert_id: str, changes) -> dict | None:
        with self._locked():
            lines = self._read_lines()
            for index, line in enumerate(lines):
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if alert.get("alert_id") != alert_id:
                    continue
                if callable(changes):
                    changes(alert)
                else:
                    alert.update(changes)
                lines[index] = json.dumps(alert, ensure_ascii=False) + "\n"
                with open(self.path, "w", encoding="utf-8") as file:
                    file.writelines(lines)
                return alert
        return None

    def get_alert(self, alert_id: str) -> dict | None:
        with self._locked():
            for line in self._read_lines():
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if alert.get("alert_id") == alert_id:
                    return alert
        return None

    def list_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> list[dict]:
        return self.search_alerts(filters, limit, offset)["items"]

    @staticmethod
    def _matches(alert, filters):
        filters = filters or {}
        for key in ("severity", "incident_status", "ai_disposition"):
            if filters.get(key) and str(alert.get(key) or "").upper() != str(filters[key]).upper():
                return False
        if filters.get("ip") and str(filters["ip"]) not in str(alert.get("ip_address") or ""):
            return False
        if filters.get("mitre") and str(filters["mitre"]).upper() not in str(alert.get("mitre_attck_id") or "").upper():
            return False
        if filters.get("q"):
            haystack = " ".join(str(alert.get(key) or "") for key in ("alert_name", "description", "raw_log"))
            if str(filters["q"]).lower() not in haystack.lower():
                return False
        if filters.get("from") or filters.get("to"):
            try:
                value = str(alert.get("timestamp") or "").replace("Z", "+00:00")
                timestamp = datetime.fromisoformat(value)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                timestamp = timestamp.astimezone(timezone.utc)
            except ValueError:
                return False
            for key, operator in (("from", lambda left, right: left < right), ("to", lambda left, right: left > right)):
                if not filters.get(key):
                    continue
                boundary = datetime.fromisoformat(str(filters[key]).replace("Z", "+00:00"))
                if boundary.tzinfo is None:
                    boundary = boundary.replace(tzinfo=timezone.utc)
                if operator(timestamp, boundary.astimezone(timezone.utc)):
                    return False
        handled = {"severity", "incident_status", "ai_disposition", "ip", "mitre", "q", "from", "to"}
        return all(alert.get(key) == value for key, value in filters.items() if key not in handled)

    def search_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> dict:
        with self._locked():
            alerts = []
            for line in self._read_lines():
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not self._matches(alert, filters):
                    continue
                alerts.append(alert)
        alerts.sort(key=lambda alert: str(alert.get("timestamp") or ""), reverse=True)
        offset = max(0, offset)
        items = alerts[offset:] if limit is None else alerts[offset:offset + max(0, limit)]
        return {"items": items, "total": len(alerts)}

    def stats(self) -> dict:
        alerts = self.list_alerts()
        count = lambda severity: sum(
            str(alert.get("severity") or "").upper() == severity for alert in alerts
        )
        return {
            "critical": count("CRITICAL"),
            "high": count("HIGH"),
            "medium": count("MEDIUM"),
            "info": count("LOW") + count("INFO"),
            "anomalies": sum("ml_anomaly_score" in alert for alert in alerts),
            "total": len(alerts),
        }

    def rule_hit_counts(self, rule_ids: list[str]) -> dict[str, int]:
        expected = set(rule_ids)
        counts = Counter()
        with self._locked():
            for line in self._read_lines():
                try:
                    rule_id = json.loads(line).get("rule_id")
                except json.JSONDecodeError:
                    continue
                if rule_id in expected:
                    counts[rule_id] += 1
        return dict(counts)


class DualWriteAlertRepository:
    def __init__(self, json_repository, sqlite_repository):
        self.json = json_repository
        self.sqlite = sqlite_repository
        try:
            self.sqlite.ensure_schema()
        except Exception as exc:
            logger.error("SQLite schema initialization failed: %s", exc)

    @contextmanager
    def _locked(self):
        lock_path = config.SQLITE_ALERT_DB + ".dual.lock"
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        with _dual_lock, open(lock_path, "a", encoding="utf-8") as lock_file:
            if fcntl:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _save_both(self, alert):
        repositories = [("SQLite", self.sqlite)]
        if getattr(config, "JSON_DUAL_WRITE_ENABLED", True):
            repositories.append(("JSON", self.json))
        failures = []
        for name, repository in repositories:
            try:
                repository.create_alert(alert)
            except Exception as exc:
                failures.append((name, exc))
                logger.error("%s alert write failed for %s: %s", name, alert.get("alert_id"), exc)
        if len(failures) == len(repositories):
            raise RuntimeError("All alert storage backends failed") from failures[0][1]
        return alert

    def _read(self, method, *args, **kwargs):
        if not getattr(config, "SQLITE_READ_ENABLED", True):
            return getattr(self.json, method)(*args, **kwargs)
        try:
            return getattr(self.sqlite, method)(*args, **kwargs)
        except Exception as exc:
            if not getattr(config, "JSON_READ_FALLBACK_ENABLED", True):
                raise
            logger.error("SQLite alert read failed; falling back to JSON: %s", exc)
            return getattr(self.json, method)(*args, **kwargs)

    def create_alert(self, alert: dict) -> dict:
        with self._locked():
            return self._save_both(copy.deepcopy(alert))

    def update_alert(self, alert_id: str, changes) -> dict | None:
        with self._locked():
            current = self.get_alert(alert_id)
            if current is None:
                return None
            updated = copy.deepcopy(current)
            changes(updated) if callable(changes) else updated.update(changes)
            return self._save_both(updated)

    def get_alert(self, alert_id: str) -> dict | None:
        return self._read("get_alert", alert_id)

    def list_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> list[dict]:
        return self._read("list_alerts", filters=filters, limit=limit, offset=offset)

    def search_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> dict:
        return self._read("search_alerts", filters=filters, limit=limit, offset=offset)

    def stats(self) -> dict:
        return self._read("stats")

    def rule_hit_counts(self, rule_ids: list[str]) -> dict[str, int]:
        return self._read("rule_hit_counts", rule_ids)

    def soc_kpis(self, from_timestamp: str, to_timestamp: str) -> dict:
        """Analytics intentionally requires the indexed primary SQLite store."""
        return self.sqlite.soc_kpis(from_timestamp, to_timestamp)

    def soc_analytics(self, from_timestamp: str, to_timestamp: str) -> dict:
        return self.sqlite.soc_analytics(from_timestamp, to_timestamp)


json_repository = JsonAlertRepository()
sqlite_repository = SQLiteAlertRepository()
alert_repository = DualWriteAlertRepository(json_repository, sqlite_repository)
