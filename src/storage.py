import json
import os
import threading
from contextlib import contextmanager

from config import config

try:
    import fcntl
except ImportError:  # Windows host fallback; production runs in Linux containers.
    fcntl = None


_lock = threading.Lock()


class JsonAlertRepository:
    @property
    def path(self):
        return config.OUTPUT_ALERT_FILE

    @contextmanager
    def _locked(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with _lock, open(self.path + ".lock", "a", encoding="utf-8") as lock_file:
            # ponytail: flock covers Docker/Linux; SQLite replaces this lock in M4.2.
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


alert_repository = JsonAlertRepository()
