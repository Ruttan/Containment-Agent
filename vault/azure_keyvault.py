"""
Azure Key Vault secrets backend.

Authenticates via `DefaultAzureCredential`, which — deliberately — never
takes a credential from this codebase or from config.yaml. It chains
through, in order: environment variables (AZURE_CLIENT_ID/SECRET/TENANT_ID,
if you've set up a service principal that way), a Managed Identity (if this
agent runs on Azure infrastructure — App Service, a VM, a container — this
is the recommended path and requires zero credentials anywhere), or an
interactive `az login` session (fine for local development).

This means: for a production deployment on Azure, you assign the agent's
Managed Identity "get" permission on secrets in your Key Vault, and no
credential of any kind needs to exist on disk or in an environment variable
at all.

Required config (under `secrets_backends.azure_keyvault`):
  vault_url    e.g. "https://your-vault-name.vault.azure.net/"

Setup:
  1. Create a Key Vault: az keyvault create --name your-vault-name --resource-group your-rg
  2. Add a secret: az keyvault secret set --vault-name your-vault-name --name anthropic-api-key --value sk-ant-...
  3. Grant access: either assign your Managed Identity the "Key Vault Secrets User"
     role (RBAC model), or add an access policy (vault access policy model),
     scoped to "get" on secrets only.

Secret names in Key Vault may only contain letters, numbers, and dashes —
use dash-case reference names in config.yaml (e.g. "anthropic-api-key", not
"anthropic_api_key").
"""

import logging
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

from .base import SecretsProvider, SecretNotFoundError


class AzureKeyVaultProvider(SecretsProvider):

    def __init__(self, vault_url: str):
        self.vault_url = vault_url
        self.credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=vault_url, credential=self.credential)
        self._cache = {}
        logging.info(f"Azure Key Vault secrets backend active — vault: {vault_url}")

    def get(self, name: str) -> str:
        if name in self._cache:
            return self._cache[name]
        try:
            secret = self.client.get_secret(name)
        except ResourceNotFoundError:
            raise SecretNotFoundError(
                f"Secret '{name}' not found in Key Vault '{self.vault_url}'. Add it with:\n"
                f"  az keyvault secret set --vault-name <your-vault-name> --name {name} --value <the-real-value>"
            )
        except ClientAuthenticationError as e:
            raise SecretNotFoundError(
                f"Could not authenticate to Key Vault '{self.vault_url}' to fetch '{name}'. "
                f"Check that DefaultAzureCredential can find valid credentials (az login, a "
                f"service principal via env vars, or a Managed Identity) and that the identity "
                f"has 'get' permission on secrets in this vault. Underlying error: {e}"
            )
        self._cache[name] = secret.value
        return secret.value
