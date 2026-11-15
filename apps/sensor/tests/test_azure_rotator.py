"""Azure app-secret rotation via Microsoft Graph, with Graph mocked."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from sensor.rotation import azure_rotator
from sensor.rotation.azure_rotator import AzureRotator

CREDS = {
    "azure_tenant_id": "00000000-0000-0000-0000-000000000001",
    "client_id": "client",
    "client_secret": "secret",
    "subscription_id": "sub",
}


def _graph_with(app: MagicMock) -> MagicMock:
    graph = MagicMock()
    graph.applications.by_application_id.return_value = app
    return graph


def test_adds_new_secret_before_removing_old():
    calls: list[str] = []
    new_key = uuid.uuid4()
    old_key = uuid.uuid4()

    app = MagicMock()

    async def add(body):
        calls.append("add")
        assert body.password_credential.display_name == "AgentGuard-rotated"
        return MagicMock(key_id=new_key)

    async def remove(body):
        calls.append("remove")
        assert body.key_id == old_key

    app.add_password.post = AsyncMock(side_effect=add)
    app.remove_password.post = AsyncMock(side_effect=remove)

    with patch.object(azure_rotator, "GraphServiceClient", return_value=_graph_with(app)):
        result = AzureRotator(CREDS).rotate_app_secret(uuid.uuid4(), "app-object-id", str(old_key))

    assert calls == ["add", "remove"]
    assert result.success is True
    assert result.new_credential_id == str(new_key)


def test_old_secret_is_kept_if_creating_new_one_fails():
    app = MagicMock()
    app.add_password.post = AsyncMock(side_effect=RuntimeError("graph down"))
    app.remove_password.post = AsyncMock()

    with patch.object(azure_rotator, "GraphServiceClient", return_value=_graph_with(app)):
        result = AzureRotator(CREDS).rotate_app_secret(uuid.uuid4(), "app-object-id", str(uuid.uuid4()))

    assert result.success is False
    assert "graph down" in result.error
    app.remove_password.post.assert_not_called()
