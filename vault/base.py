"""
Base interface every secrets backend must implement.

The whole point of this package: config.yaml never holds a real secret
value. Every credential field in config.yaml holds a *reference name*
(e.g. "anthropic-api-key"), and the actual value only exists inside
whichever backend is configured — Azure Key Vault or a KeePass database.
`resolver.py` looks up each reference name via whichever provider is active
and swaps in the real value, once, at startup. Nothing downstream of that
(connectors, notifiers, evaluator) changes — they still just read
config["anthropic_api_key"] etc. and get the real value.

NOTE: this package is deliberately named `vault`, not `secrets` — a package
literally named `secrets` sitting at the project root would shadow Python's
standard library `secrets` module for any code run from this directory,
including inside dependencies like azure-identity that use it internally.
"""

from abc import ABC, abstractmethod


class SecretNotFoundError(Exception):
    """Raised when a referenced secret name doesn't exist in the backend."""
    pass


class SecretsProvider(ABC):

    @abstractmethod
    def get(self, name: str) -> str:
        """
        Fetch a secret's real value by its reference name.
        Must raise SecretNotFoundError (with a message telling the user how
        to add it) if the name doesn't exist in the backend.
        """
        pass
