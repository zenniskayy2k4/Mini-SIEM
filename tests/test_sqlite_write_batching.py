import tempfile
import threading
from pathlib import Path

from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from src.storage import BoundedSQLiteAlertWriter, DualWriteAlertRepository, JsonAlertRepository


class _CaptureRepository:
    def __init__(self):
        self.batches = []
        self.written = threading.Event()

    def create_alerts(self, alerts):
        self.batches.append([alert["alert_id"] for alert in alerts])
        self.written.set()


def _alerts(count):
    return [
        build_alert(
            alert_id=f"ALT-BATCH-{index}", alert_name="Batch test", severity="LOW",
            source_type="HIDS_LOG", description="offline test",
            timestamp=f"2026-08-29T12:00:{index:02d}Z",
        )
        for index in range(count)
    ]


def test_bounded_sqlite_write_batching():
    capture = _CaptureRepository()
    writer = BoundedSQLiteAlertWriter(capture, batch_size=3, flush_delay=0.2, capacity=3)
    for alert in _alerts(3):
        writer.submit(alert)
    writer.flush()
    writer.submit(_alerts(4)[3])
    writer.shutdown()
    assert capture.batches == [
        ["ALT-BATCH-0", "ALT-BATCH-1", "ALT-BATCH-2"], ["ALT-BATCH-3"],
    ]
    try:
        writer.submit(_alerts(1)[0])
        raise AssertionError("Shutdown writer accepted another alert")
    except RuntimeError:
        pass

    delayed = _CaptureRepository()
    writer = BoundedSQLiteAlertWriter(delayed, batch_size=10, flush_delay=0.02, capacity=10)
    writer.submit(_alerts(1)[0])
    assert delayed.written.wait(0.5), "Maximum flush delay was not enforced"
    writer.shutdown()

    original = config.OUTPUT_ALERT_FILE, config.JSON_DUAL_WRITE_ENABLED
    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        config.OUTPUT_ALERT_FILE = str(root / "alerts.jsonl")
        config.JSON_DUAL_WRITE_ENABLED = True
        sqlite = SQLiteAlertRepository(str(root / "alerts.db"))
        writer = BoundedSQLiteAlertWriter(sqlite, batch_size=3, flush_delay=0.2, capacity=3)
        repository = DualWriteAlertRepository(JsonAlertRepository(), sqlite, writer)
        try:
            for alert in _alerts(5):
                repository.create_alert(alert)
            assert Path(config.OUTPUT_ALERT_FILE).read_text(encoding="utf-8").count("\n") == 5
            assert [alert["alert_id"] for alert in repository.list_alerts()] == [
                "ALT-BATCH-4", "ALT-BATCH-3", "ALT-BATCH-2", "ALT-BATCH-1", "ALT-BATCH-0",
            ]
        finally:
            repository.shutdown()
        config.JSON_DUAL_WRITE_ENABLED = False
        sqlite = SQLiteAlertRepository(str(root / "sqlite-only.db"))
        writer = BoundedSQLiteAlertWriter(sqlite, batch_size=3, flush_delay=0.2, capacity=3)
        repository = DualWriteAlertRepository(JsonAlertRepository(), sqlite, writer)
        try:
            repository.create_alert(_alerts(1)[0])
            assert sqlite.stats()["total"] == 1
        finally:
            repository.shutdown()
            config.OUTPUT_ALERT_FILE, config.JSON_DUAL_WRITE_ENABLED = original


if __name__ == "__main__":
    test_bounded_sqlite_write_batching()
    print("M26.2 bounded SQLite write batching passed")
