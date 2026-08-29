import threading
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.handler import LogHandler, WindowsEventHandler
from src.ingestion_queue import BoundedIngestionQueue


def test_ingestion_queue():
    queue = BoundedIngestionQueue(1)
    started = threading.Event()
    release = threading.Event()
    processed = []

    def process(value):
        if value == 1:
            started.set()
            release.wait(2)
        processed.append(value)

    assert queue.submit(process, 1)
    assert started.wait(1)
    assert queue.submit(process, 2)
    producer = threading.Thread(target=lambda: queue.submit(process, 3))
    producer.start()
    producer.join(0.05)
    assert producer.is_alive()
    assert queue.status() == {
        "status": "saturated", "depth": 1, "capacity": 1,
        "backpressure_total": 1, "rejected_total": 0, "dropped_total": 0,
    }

    release.set()
    producer.join(1)
    queue.drain()
    assert processed == [1, 2, 3]
    with patch("src.ingestion_queue.logger.exception") as log_failure:
        assert queue.submit(lambda: 1 / 0)
        queue.drain()
        log_failure.assert_called_once()
    assert queue.status()["dropped_total"] == 1
    queue.shutdown()
    with patch("src.ingestion_queue.logger.warning") as log_rejection:
        assert queue.submit(process, 4) is False
        log_rejection.assert_called_once()
    assert queue.status()["rejected_total"] == 1

    class Detector:
        def __init__(self):
            self.events = []

        def analyze(self, line):
            self.events.append(("HIDS_LOG", line.strip()))

        def analyze_windows_event(self, event):
            self.events.append(("WINDOWS_EVENT", event["event_id"]))

    with tempfile.TemporaryDirectory() as directory:
        paths = [Path(directory, name) for name in ("auth.log", "windows.jsonl")]
        for path in paths:
            path.touch()
        detector = Detector()
        shared = BoundedIngestionQueue(2)
        handlers = [
            LogHandler(paths[0], detector, object(), object(), ingestion_queue=shared),
            WindowsEventHandler(paths[1], detector, object(), object(), ingestion_queue=shared),
        ]
        try:
            paths[0].write_text("failed login\n", encoding="utf-8")
            paths[1].write_text('{"event_id":"win-1"}\n', encoding="utf-8")
            for handler, path in zip(handlers, paths):
                handler.on_modified(SimpleNamespace(src_path=str(path)))
            shared.drain()
            assert detector.events == [
                ("HIDS_LOG", "failed login"), ("WINDOWS_EVENT", "win-1"),
            ]
        finally:
            for handler in handlers:
                handler.file_handle.close()
            shared.shutdown()


if __name__ == "__main__":
    test_ingestion_queue()
    print("M25.3 bounded ingestion queue passed")
