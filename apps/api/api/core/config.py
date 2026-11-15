from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "AgentGuard API"
    debug: bool = False
    api_v1_prefix: str = "/v1"

    # Database
    database_url: str  # postgresql+asyncpg://user:pass@host/db
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Auth (Clerk)
    clerk_publishable_key: str = ""
    clerk_secret_key: str = ""
    clerk_jwt_verification_key: str = ""  # PEM public key for offline JWT verification

    # AWS SQS (event bus)
    aws_region: str = "us-east-1"
    sqs_scan_queue_url: str = ""
    sqs_rotation_queue_url: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Vault (secrets backend)
    vault_addr: str = "http://localhost:8200"
    vault_token: str = ""

    # Sensor gRPC
    sensor_grpc_port: int = 50051
    sensor_auth_secret: str = ""

    # OPA
    opa_url: str = "http://localhost:8181"

    # Behavioral ClickHouse
    clickhouse_url: str = ""
    clickhouse_user: str = "default"
    clickhouse_password: str = ""

    # Notification integrations
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""

    # Internal sensor auth (shared secret, distinct from Clerk JWTs)
    sensor_auth_secret: str = ""
    sensor_callback_url: str = "http://localhost:8001"


@lru_cache
def get_settings() -> Settings:
    return Settings()
