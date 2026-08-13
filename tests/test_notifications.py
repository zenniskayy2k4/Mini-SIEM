import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.notifier import WebhookNotifier


def test_notifications():
    with tempfile.TemporaryDirectory() as directory:
        original = (
            config.NOTIFICATION_LOG_FILE,
            config.NOTIFICATION_MAX_ATTEMPTS,
            config.NOTIFICATION_TIMEOUT_SECONDS,
        )
        config.NOTIFICATION_LOG_FILE = str(Path(directory, "notifications.jsonl"))
        config.NOTIFICATION_MAX_ATTEMPTS = 2
        config.NOTIFICATION_TIMEOUT_SECONDS = 1
        try:
            alert = build_alert(
                alert_name="SSH Brute Force Attempt",
                severity="HIGH",
                source_type="HIDS_LOG",
                description="contains secret=do-not-send",
                raw_log="Authorization: Bearer do-not-send",
                ip_address="192.0.2.64",
            )
            received = []

            class WebhookHandler(BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    received.append(json.loads(self.rfile.read(length)))
                    self.send_response(204)
                    self.end_headers()

                def log_message(self, *_args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            success = Mock()
            success.raise_for_status.return_value = None
            notifier = WebhookNotifier(f"http://127.0.0.1:{server.server_port}/token-secret", "generic")
            try:
                sent = notifier.notify(alert)
                duplicate = notifier.notify(alert)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join()
            assert sent["status"] == "SENT"
            assert duplicate["status"] == "DEDUPLICATED"
            assert len(received) == 1
            serialized_payload = json.dumps(received[0])
            assert "raw_log" not in serialized_payload
            assert "do-not-send" not in serialized_payload
            assert "token-secret" not in Path(config.NOTIFICATION_LOG_FILE).read_text(encoding="utf-8")
            reloaded = WebhookNotifier(f"http://127.0.0.1:{server.server_port}/token-secret", "generic")
            with patch("src.notifier.requests.post") as post:
                assert reloaded.notify(alert)["status"] == "DEDUPLICATED"
                post.assert_not_called()

            review = build_alert(
                alert_name="Review requested",
                severity="MEDIUM",
                source_type="HIDS_LOG",
                description="AI escalation",
                ai_disposition="REQUIRES_HUMAN_REVIEW",
            )
            notifier = WebhookNotifier("https://hooks.example.test/retry", "discord")
            with patch(
                "src.notifier.requests.post",
                side_effect=[requests.Timeout(), success],
            ) as post:
                retried = notifier.notify(review)
            assert retried["status"] == "SENT"
            assert retried["attempts"] == 2
            assert post.call_count == 2
            assert "content" in post.call_args.kwargs["json"]

            failed_alert = build_alert(
                alert_name="Webhook failure",
                severity="CRITICAL",
                source_type="HIDS_LOG",
                description="bounded retry",
            )
            notifier = WebhookNotifier("https://hooks.example.test/failure-secret", "generic")
            with patch("src.notifier.requests.post", side_effect=requests.Timeout()) as post:
                failed = notifier.notify(failed_alert)
            assert failed["status"] == "FAILED"
            assert failed["error"] == "Timeout"
            assert post.call_count == 2

            low = build_alert(
                alert_name="Low priority",
                severity="LOW",
                source_type="HIDS_LOG",
                description="no notification",
            )
            with patch("src.notifier.requests.post") as post:
                assert notifier.notify(low) is None
                post.assert_not_called()

            pipeline_notifier = WebhookNotifier("https://hooks.example.test/pipeline", "generic")

            class ImmediateAnalyst:
                @staticmethod
                def enrich_async(item, on_complete):
                    item["ai_disposition"] = "REQUIRES_HUMAN_REVIEW"
                    on_complete(item)

            with (
                patch("src.alert_pipeline.upsert_alert"),
                patch("src.alert_pipeline.notification_service", pipeline_notifier),
                patch("src.notifier.requests.post", return_value=success) as post,
            ):
                persist_and_enrich(build_alert(
                    alert_name="Pipeline notification",
                    severity="CRITICAL",
                    source_type="HIDS_LOG",
                    description="pipeline callback",
                ), ImmediateAnalyst())
                assert post.call_count == 1

            audit = [json.loads(line) for line in Path(config.NOTIFICATION_LOG_FILE).read_text(encoding="utf-8").splitlines()]
            assert [event["status"] for event in audit] == ["SENT", "SENT", "FAILED", "SENT"]
            assert "failure-secret" not in json.dumps(audit)
        finally:
            (
                config.NOTIFICATION_LOG_FILE,
                config.NOTIFICATION_MAX_ATTEMPTS,
                config.NOTIFICATION_TIMEOUT_SECONDS,
            ) = original


if __name__ == "__main__":
    test_notifications()
    print("M6.4 notifications passed")
