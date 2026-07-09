"""
Builds the configured secrets provider from config.yaml's `secrets_provider`
and `secrets_backends` blocks. Exactly one backend is active at a time.
"""


def build_secrets_provider(config: dict):
    provider_name = config.get("secrets_provider")
    if not provider_name:
        raise RuntimeError(
            "No `secrets_provider` set in config.yaml. Set it to 'azure_keyvault' or 'keepass', "
            "and fill in the matching block under `secrets_backends`. See config.example.yaml."
        )

    backends_cfg = config.get("secrets_backends", {}) or {}

    if provider_name == "azure_keyvault":
        from .azure_keyvault import AzureKeyVaultProvider
        cfg = backends_cfg.get("azure_keyvault") or {}
        if not cfg.get("vault_url"):
            raise RuntimeError("secrets_backends.azure_keyvault.vault_url is required.")
        return AzureKeyVaultProvider(vault_url=cfg["vault_url"])

    elif provider_name == "keepass":
        from .keepass_provider import KeePassProvider
        cfg = backends_cfg.get("keepass") or {}
        if not cfg.get("database_path"):
            raise RuntimeError("secrets_backends.keepass.database_path is required.")
        return KeePassProvider(database_path=cfg["database_path"], keyfile_path=cfg.get("keyfile_path"))

    else:
        raise RuntimeError(
            f"Unknown secrets_provider '{provider_name}'. Must be 'azure_keyvault' or 'keepass'."
        )
