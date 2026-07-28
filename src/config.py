"""
Configuration and Secrets Management for VendorGuard ADK.
Supports Google Cloud Secret Manager with .env fallback.
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class SecretManager:
    """Secret Manager wrapper supporting GCP Secret Manager with local env fallback."""

    def __init__(self, project_id: Optional[str] = None):
        """Initializes SecretManager with an optional GCP project ID.

        Args:
            project_id (Optional[str], optional): Google Cloud project ID for Secret Manager API access. Defaults to None.
        """
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT")
        self._gcp_client = None

    def _get_gcp_client(self):
        """Retrieves or initializes the Google Cloud Secret Manager client instance.

        Returns:
            Optional[secretmanager.SecretManagerServiceClient]: Secret manager client object or False if unavailable.
        """
        if self._gcp_client is None:
            try:
                from google.cloud import secretmanager
                self._gcp_client = secretmanager.SecretManagerServiceClient()
            except Exception:
                self._gcp_client = False
        return self._gcp_client

    def get_secret(self, secret_id: str, default: Optional[str] = None) -> Optional[str]:
        """Fetch secret from Google Cloud Secret Manager if available, otherwise fallback to env var.

        Args:
            secret_id (str): Identifier or key name of the secret to retrieve.
            default (Optional[str], optional): Default fallback value if secret is not found. Defaults to None.

        Returns:
            Optional[str]: Secret string value if found, otherwise default.
        """
        # 1. Check local environment variable first if set explicitly
        env_val = os.getenv(secret_id.upper()) or os.getenv(secret_id)
        if env_val:
            return env_val

        # 2. Attempt GCP Secret Manager if project ID is available
        if self.project_id:
            client = self._get_gcp_client()
            if client and client is not False:
                try:
                    name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
                    response = client.access_secret_version(request={"name": name})
                    return response.payload.data.decode("UTF-8")
                except Exception:
                    pass

        return default


# Config instance
secret_manager = SecretManager()

class AppConfig:
    PROJECT_NAME: str = "VendorGuard ADK"
    ENV: str = os.getenv("ENV", "development")
    GEMINI_API_KEY: Optional[str] = secret_manager.get_secret("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    VECTOR_STORE_PATH: str = os.getenv("VECTOR_STORE_PATH", "./data/vector_db")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    OPENTELEMETRY_ENDPOINT: Optional[str] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

config = AppConfig()
