import logging
import queue
import threading


logger = logging.getLogger(__name__)
_STOP = object()


class BoundedIngestionQueue:
    """Single-worker queue that blocks producers instead of dropping telemetry."""

    def __init__(self, capacity: int):
        self._queue = queue.Queue(maxsize=max(1, int(capacity)))
        self._condition = threading.Condition()
        self._accepting = True
        self._submitters = 0
        self._backpressure_total = 0
        self._rejected_total = 0
        self._dropped_total = 0
        self._worker = threading.Thread(
            target=self._run, name="ingestion-worker", daemon=True,
        )
        self._worker.start()

    def submit(self, callback, *args) -> bool:
        with self._condition:
            if not self._accepting:
                self._rejected_total += 1
                logger.warning("[-] Ingestion rejected after queue shutdown")
                return False
            if self._queue.full():
                self._backpressure_total += 1
            self._submitters += 1
        try:
            self._queue.put((callback, args))
        finally:
            with self._condition:
                self._submitters -= 1
                self._condition.notify_all()
        return True

    def status(self) -> dict:
        depth = self._queue.qsize()
        capacity = self._queue.maxsize
        with self._condition:
            return {
                "status": "saturated" if depth >= capacity else "healthy",
                "depth": depth,
                "capacity": capacity,
                "backpressure_total": self._backpressure_total,
                "rejected_total": self._rejected_total,
                "dropped_total": self._dropped_total,
            }

    def drain(self) -> None:
        self._queue.join()

    def shutdown(self) -> None:
        with self._condition:
            if not self._accepting:
                return
            self._accepting = False
            while self._submitters:
                self._condition.wait()
        self._queue.put(_STOP)
        self._queue.join()
        self._worker.join()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                callback, args = item
                callback(*args)
            except Exception:
                with self._condition:
                    self._dropped_total += 1
                logger.exception("[-] Ingestion worker failed to process an event")
            finally:
                self._queue.task_done()
