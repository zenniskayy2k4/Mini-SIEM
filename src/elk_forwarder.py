import requests
import json
from datetime import datetime, timezone
from config import config

class ELKForwarder:
    """
    Responsible for forwarding alert documents to an Elasticsearch (ELK) endpoint.
    """

    def send_alert(self, alert):
        """
        Send a single alert to the configured Elasticsearch endpoint.

        If ELK integration is disabled via configuration, this is a no-op.
        """
        if not config.ELK_ENABLED:
            return

        # Prepare the payload to send
        payload = alert.copy()
        # Add an '@timestamp' field in UTC to assist Elasticsearch indexing
        payload["@timestamp"] = datetime.now(timezone.utc).isoformat()

        try:
            # Send an HTTP POST to the configured Elasticsearch URL
            # (typically Elasticsearch listens on port 9200)
            response = requests.post(
                config.ELK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=2  # short timeout to avoid blocking the main thread
            )
            if response.status_code in (200, 201):
                pass  # successfully accepted/created
        except requests.exceptions.ConnectionError:
            # Could not connect to ELK (expected if ELK is not running).
            # Silently ignore to avoid spamming logs in normal setups.
            pass
        except Exception as e:
            print(f"[ELK Error] {e}")