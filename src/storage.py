import copy
import json
import logging
import os
import threading
from contextlib import contextmanager

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
        with self._locked():
            alerts = []
            for line in reversed(self._read_lines()):
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if filters and any(alert.get(key) != value for key, value in filters.items()):
                    continue
                alerts.append(alert)
        offset = max(0, offset)
        return alerts[offset:] if limit is None else alerts[offset:offset + max(0, limit)]


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
        failures = []
        for name, repository in (("SQLite", self.sqlite), ("JSON", self.json)):
            try:
                repository.create_alert(alert)
            except Exception as exc:
                failures.append((name, exc))
                logger.error("%s alert write failed for %s: %s", name, alert.get("alert_id"), exc)
        if len(failures) == 2:
            raise RuntimeError("All alert storage backends failed") from failures[0][1]
        return alert

    def create_alert(self, alert: dict) -> dict:
        with self._locked():
            return self._save_both(copy.deepcopy(alert))

    def update_alert(self, alert_id: str, changes) -> dict | None:
        with self._locked():
            current = self.json.get_alert(alert_id) or self.sqlite.get_alert(alert_id)
            if current is None:
                return None
            updated = copy.deepcopy(current)
            changes(updated) if callable(changes) else updated.update(changes)
            return self._save_both(updated)

    def get_alert(self, alert_id: str) -> dict | None:
        return self.json.get_alert(alert_id)

    def list_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> list[dict]:
        return self.json.list_alerts(filters=filters, limit=limit, offset=offset)


json_repository = JsonAlertRepository()
sqlite_repository = SQLiteAlertRepository()
alert_repository = DualWriteAlertRepository(json_repository, sqlite_repository)
