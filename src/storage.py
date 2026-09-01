import atexit
import copy
from collections import Counter
import json
import logging
import os
import queue
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from config import config
from src.alert_schema import normalize_alert
from src.sqlite_store import SQLiteAlertRepository

try:
    import fcntl
except ImportError:  # Windows host fallback; production runs in Linux containers.
    fcntl = None


logger = logging.getLogger(__name__)
_json_lock = threading.Lock()
_dual_lock = threading.Lock()
_STOP = object()


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
        alert = normalize_alert(alert)
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
                    alert = normalize_alert(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if alert.get("alert_id") != alert_id:
                    continue
                if callable(changes):
                    changes(alert)
                else:
                    alert.update(changes)
                normalize_alert(alert)
                lines[index] = json.dumps(alert, ensure_ascii=False) + "\n"
                with open(self.path, "w", encoding="utf-8") as file:
                    file.writelines(lines)
                return alert
        return None

    def get_alert(self, alert_id: str) -> dict | None:
        with self._locked():
            for line in self._read_lines():
                try:
                    alert = normalize_alert(json.loads(line))
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
        for key in ("severity", "incident_status", "ai_disposition", "assigned_to"):
            if filters.get(key) and str(alert.get(key) or "").upper() != str(filters[key]).upper():
                return False
        if filters.get("unassigned") and str(alert.get("assigned_to") or "").strip():
            return False
        if filters.get("open_incidents"):
            status = str(alert.get("incident_status") or "").upper()
            if not alert.get("incident_id") or status in {"RESOLVED", "FALSE_POSITIVE"}:
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
        handled = {
            "severity", "incident_status", "ai_disposition", "assigned_to", "unassigned",
            "open_incidents", "ip", "mitre", "q", "from", "to",
        }
        return all(alert.get(key) == value for key, value in filters.items() if key not in handled)

    def search_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> dict:
        with self._locked():
            alerts = []
            for line in self._read_lines():
                try:
                    alert = normalize_alert(json.loads(line))
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


class BoundedSQLiteAlertWriter:
    """FIFO SQLite batches backed by the durable JSON mirror."""

    def __init__(self, repository, batch_size, flush_delay, capacity):
        self.repository = repository
        self.batch_size = max(1, int(batch_size))
        self.flush_delay = max(0.001, float(flush_delay))
        self._queue = queue.Queue(maxsize=max(self.batch_size, int(capacity)))
        self._condition = threading.Condition()
        self._accepting = True
        self._submitters = 0
        self._error = None
        self._worker = threading.Thread(
            target=self._run, name="sqlite-alert-writer", daemon=True,
        )
        self._worker.start()

    def submit(self, alert):
        with self._condition:
            if not self._accepting:
                raise RuntimeError("SQLite alert writer is shut down")
            self._submitters += 1
        try:
            self._queue.put(copy.deepcopy(alert))
        finally:
            with self._condition:
                self._submitters -= 1
                self._condition.notify_all()

    def flush(self):
        self._queue.join()
        if self._error is not None:
            raise RuntimeError("SQLite alert batch write failed") from self._error

    def shutdown(self):
        with self._condition:
            if not self._accepting:
                return
            self._accepting = False
            while self._submitters:
                self._condition.wait()
        self._queue.put(_STOP)
        self._queue.join()
        self._worker.join()

    def _run(self):
        while True:
            first = self._queue.get()
            if first is _STOP:
                self._queue.task_done()
                return
            batch = [first]
            stop = False
            deadline = time.monotonic() + self.flush_delay
            while len(batch) < self.batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is _STOP:
                    stop = True
                    break
                batch.append(item)
            try:
                self.repository.create_alerts(batch)
            except Exception as exc:
                self._error = exc
                logger.error("SQLite alert batch write failed: %s", exc)
            finally:
                for _ in batch:
                    self._queue.task_done()
                if stop:
                    self._queue.task_done()
            if stop:
                return


class DualWriteAlertRepository:
    def __init__(self, json_repository, sqlite_repository, sqlite_writer=None):
        self.json = json_repository
        self.sqlite = sqlite_repository
        self.sqlite_writer = sqlite_writer
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
        json_enabled = getattr(config, "JSON_DUAL_WRITE_ENABLED", True)
        sqlite_async = self.sqlite_writer is not None and json_enabled
        failures = []
        try:
            if sqlite_async:
                self.sqlite_writer.submit(alert)
            else:
                self.sqlite.create_alert(alert)
        except Exception as exc:
            failures.append(("SQLite", exc))
            logger.error("SQLite alert write failed for %s: %s", alert.get("alert_id"), exc)
        if json_enabled:
            try:
                self.json.create_alert(alert)
            except Exception as exc:
                failures.append(("JSON", exc))
                logger.error("JSON alert write failed for %s: %s", alert.get("alert_id"), exc)
                if sqlite_async:
                    try:
                        self.sqlite_writer.flush()
                    except Exception as sqlite_exc:
                        failures.append(("SQLite", sqlite_exc))
        if len({name for name, _ in failures}) == 1 + int(json_enabled):
            raise RuntimeError("All alert storage backends failed") from failures[0][1]
        return alert

    def _read(self, method, *args, **kwargs):
        if not getattr(config, "SQLITE_READ_ENABLED", True):
            return getattr(self.json, method)(*args, **kwargs)
        try:
            self._flush_sqlite()
            return getattr(self.sqlite, method)(*args, **kwargs)
        except Exception as exc:
            if not getattr(config, "JSON_READ_FALLBACK_ENABLED", True):
                raise
            logger.error("SQLite alert read failed; falling back to JSON: %s", exc)
            return getattr(self.json, method)(*args, **kwargs)

    def _flush_sqlite(self):
        if self.sqlite_writer is not None:
            self.sqlite_writer.flush()

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

    def create_detection_feedback(
        self, alert_id: str, classification: str, reason: str, actor: str, role=None,
    ) -> dict | None:
        self._flush_sqlite()
        return self.sqlite.create_detection_feedback(
            alert_id, classification, reason, actor, role,
        )

    def rule_quality(self, from_timestamp: str, to_timestamp: str) -> list[dict]:
        self._flush_sqlite()
        return self.sqlite.rule_quality(from_timestamp, to_timestamp)

    def create_detection_exception(
        self, scope_type, scope_value, reason, creator, role=None, expires_at=None,
    ) -> dict:
        return self.sqlite.create_detection_exception(
            scope_type, scope_value, reason, creator, role, expires_at,
        )

    def list_detection_exceptions(self) -> list[dict]:
        return self.sqlite.list_detection_exceptions()

    def delete_detection_exception(self, exception_id, actor, role=None) -> bool:
        return self.sqlite.delete_detection_exception(exception_id, actor, role)

    def match_detection_exception(self, alert: dict) -> dict | None:
        return self.sqlite.match_detection_exception(alert)

    def create_alert_suppression_policy(
        self, rule_id, correlation_key, window_seconds, creator, role=None,
    ) -> dict:
        return self.sqlite.create_alert_suppression_policy(
            rule_id, correlation_key, window_seconds, creator, role,
        )

    def list_alert_suppression_policies(self) -> list[dict]:
        return self.sqlite.list_alert_suppression_policies()

    def delete_alert_suppression_policy(self, policy_id, actor, role=None) -> bool:
        return self.sqlite.delete_alert_suppression_policy(policy_id, actor, role)

    def apply_alert_suppression(self, alert: dict) -> dict:
        with self._locked():
            self._flush_sqlite()
            result = self.sqlite.apply_alert_suppression(copy.deepcopy(alert))
            if result["suppressed"]:
                self._save_both(copy.deepcopy(result["alert"]))
            return result

    def soc_kpis(self, from_timestamp: str, to_timestamp: str) -> dict:
        """Analytics intentionally requires the indexed primary SQLite store."""
        self._flush_sqlite()
        return self.sqlite.soc_kpis(from_timestamp, to_timestamp)

    def soc_analytics(self, from_timestamp: str, to_timestamp: str) -> dict:
        self._flush_sqlite()
        return self.sqlite.soc_analytics(from_timestamp, to_timestamp)

    def flush(self):
        self._flush_sqlite()

    def shutdown(self):
        if self.sqlite_writer is not None:
            self.sqlite_writer.shutdown()


json_repository = JsonAlertRepository()
sqlite_repository = SQLiteAlertRepository()
sqlite_writer = BoundedSQLiteAlertWriter(
    sqlite_repository,
    config.SQLITE_WRITE_BATCH_SIZE,
    config.SQLITE_WRITE_FLUSH_SECONDS,
    config.INGESTION_QUEUE_CAPACITY,
)
alert_repository = DualWriteAlertRepository(json_repository, sqlite_repository, sqlite_writer)
atexit.register(alert_repository.shutdown)
