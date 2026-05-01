"""Vault connectors — metadata-only (no secret values ever read)."""
from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class VaultSecretMeta:
    name: str
    vault_id: str
    vault_type: str
    created_at: str | None = None
    last_rotated: str | None = None
    expires_at: str | None = None
    tags: dict = field(default_factory=dict)


class VaultConnector(ABC):
    vault_type: str = ""

    @abstractmethod
    async def list_secrets(self) -> list[VaultSecretMeta]: ...

    @abstractmethod
    async def rotate_secret(self, name: str) -> bool: ...

    async def health_check(self) -> bool:
        try:
            await self.list_secrets()
            return True
        except Exception:
            return False


class EnvVaultConnector(VaultConnector):
    """Scans process environment for secrets via regex heuristics."""

    vault_type = "env"

    # Patterns that suggest a variable holds a secret
    _SECRET_KEYS = re.compile(
        r"(key|secret|token|password|passwd|pwd|credential|api_key|auth|cert|private)",
        re.IGNORECASE,
    )

    def __init__(self, vault_id: str = "env-default"):
        self.vault_id = vault_id

    async def list_secrets(self) -> list[VaultSecretMeta]:
        results = []
        for k, v in os.environ.items():
            if self._SECRET_KEYS.search(k) and v:
                results.append(
                    VaultSecretMeta(
                        name=k,
                        vault_id=self.vault_id,
                        vault_type="env",
                        created_at=None,
                    )
                )
        return results

    async def rotate_secret(self, name: str) -> bool:
        return False  # env vars can't be rotated programmatically


class AWSSecretsManagerConnector(VaultConnector):
    vault_type = "aws_sm"

    def __init__(self, vault_id: str, region: str, access_key: str, secret_key: str):
        self.vault_id = vault_id
        self.region = region
        self._access_key = access_key
        self._secret_key = secret_key

    def _client(self):
        try:
            import boto3  # type: ignore
            return boto3.client(
                "secretsmanager",
                region_name=self.region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
        except ImportError as exc:
            raise RuntimeError("boto3 not installed — pip install boto3") from exc

    async def list_secrets(self) -> list[VaultSecretMeta]:
        import asyncio
        loop = asyncio.get_running_loop()
        client = self._client()

        def _fetch():
            secrets, token = [], None
            while True:
                kwargs = {"MaxResults": 100}
                if token:
                    kwargs["NextToken"] = token
                resp = client.list_secrets(**kwargs)
                secrets.extend(resp.get("SecretList", []))
                token = resp.get("NextToken")
                if not token:
                    break
            return secrets

        raw = await loop.run_in_executor(None, _fetch)
        results = []
        for s in raw:
            results.append(VaultSecretMeta(
                name=s["Name"],
                vault_id=self.vault_id,
                vault_type="aws_sm",
                created_at=s.get("CreatedDate", "").isoformat() if s.get("CreatedDate") else None,
                last_rotated=s.get("LastRotatedDate", "").isoformat() if s.get("LastRotatedDate") else None,
                expires_at=None,
                tags={t["Key"]: t["Value"] for t in s.get("Tags", [])},
            ))
        return results

    async def rotate_secret(self, name: str) -> bool:
        import asyncio
        loop = asyncio.get_running_loop()
        client = self._client()
        try:
            await loop.run_in_executor(None, lambda: client.rotate_secret(SecretId=name))
            return True
        except Exception:
            return False


class AzureKeyVaultConnector(VaultConnector):
    vault_type = "azure_kv"

    def __init__(self, vault_id: str, vault_url: str, tenant_id: str,
                 client_id: str, client_secret: str):
        self.vault_id = vault_id
        self.vault_url = vault_url
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret

    def _client(self):
        try:
            from azure.identity import ClientSecretCredential  # type: ignore
            from azure.keyvault.secrets import SecretClient  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "azure-keyvault-secrets + azure-identity not installed"
            ) from exc
        cred = ClientSecretCredential(self._tenant_id, self._client_id, self._client_secret)
        return SecretClient(vault_url=self.vault_url, credential=cred)

    async def list_secrets(self) -> list[VaultSecretMeta]:
        import asyncio
        loop = asyncio.get_running_loop()
        client = self._client()

        def _fetch():
            return list(client.list_properties_of_secrets())

        props = await loop.run_in_executor(None, _fetch)
        results = []
        for p in props:
            results.append(VaultSecretMeta(
                name=p.name,
                vault_id=self.vault_id,
                vault_type="azure_kv",
                created_at=p.created_on.isoformat() if p.created_on else None,
                last_rotated=p.updated_on.isoformat() if p.updated_on else None,
                expires_at=p.expires_on.isoformat() if p.expires_on else None,
                tags=dict(p.tags or {}),
            ))
        return results

    async def rotate_secret(self, name: str) -> bool:
        return False  # Azure KV rotation requires rotation policy setup


class HashiCorpVaultConnector(VaultConnector):
    vault_type = "hashicorp"

    def __init__(self, vault_id: str, addr: str, token: str, mount_path: str = "secret"):
        self.vault_id = vault_id
        self.addr = addr.rstrip("/")
        self._token = token
        self.mount_path = mount_path

    async def list_secrets(self) -> list[VaultSecretMeta]:
        try:
            import httpx  # type: ignore
        except ImportError as exc:
            raise RuntimeError("httpx not installed") from exc

        headers = {"X-Vault-Token": self._token}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.request(
                "LIST",
                f"{self.addr}/v1/{self.mount_path}/metadata/",
                headers=headers,
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            keys = resp.json().get("data", {}).get("keys", [])

        results = []
        for k in keys:
            if k.endswith("/"):
                continue
            results.append(VaultSecretMeta(
                name=k,
                vault_id=self.vault_id,
                vault_type="hashicorp",
            ))
        return results

    async def rotate_secret(self, name: str) -> bool:
        return False  # HashiCorp rotation requires custom rotation script


class GCPSecretManagerConnector(VaultConnector):
    vault_type = "gcp_sm"

    def __init__(self, vault_id: str, project_id: str, credentials_json: str):
        self.vault_id = vault_id
        self.project_id = project_id
        self._credentials_json = credentials_json

    def _client(self):
        try:
            import json

            from google.cloud import secretmanager  # type: ignore
            from google.oauth2 import service_account  # type: ignore
            creds_dict = json.loads(self._credentials_json)
            creds = service_account.Credentials.from_service_account_info(creds_dict)
            return secretmanager.SecretManagerServiceClient(credentials=creds)
        except ImportError as exc:
            raise RuntimeError("google-cloud-secret-manager not installed") from exc

    async def list_secrets(self) -> list[VaultSecretMeta]:
        import asyncio
        loop = asyncio.get_running_loop()
        client = self._client()

        def _fetch():
            return list(client.list_secrets(
                request={"parent": f"projects/{self.project_id}"}
            ))

        secrets = await loop.run_in_executor(None, _fetch)
        results = []
        for s in secrets:
            name = s.name.split("/")[-1]
            results.append(VaultSecretMeta(
                name=name,
                vault_id=self.vault_id,
                vault_type="gcp_sm",
                created_at=s.create_time.isoformat() if s.create_time else None,
                tags=dict(s.labels or {}),
            ))
        return results

    async def rotate_secret(self, name: str) -> bool:
        return False


CONNECTOR_TYPES = {
    "aws_sm": AWSSecretsManagerConnector,
    "azure_kv": AzureKeyVaultConnector,
    "hashicorp": HashiCorpVaultConnector,
    "gcp_sm": GCPSecretManagerConnector,
    "env": EnvVaultConnector,
}


def build_connector(vault_config: dict) -> VaultConnector:
    vtype = vault_config["vault_type"]
    cls = CONNECTOR_TYPES.get(vtype)
    if cls is None:
        raise ValueError(f"Unknown vault type: {vtype}")
    if vtype == "env":
        return cls(vault_id=vault_config["vault_id"])
    params = {k: v for k, v in vault_config.items() if k not in ("vault_type",)}
    return cls(**params)
