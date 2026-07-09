"""
KeePass secrets backend.

Every credential the agent needs (Anthropic API key, platform client
secrets, Slack webhook URL, SMTP password, SIEM tokens, etc.) is stored as
an *entry* in your existing .kdbx database, titled with the exact reference
name used in config.yaml, with the real secret value in that entry's
Password field.

The one thing this can't avoid: unlocking a KeePass database requires a
master password (or key file) — that's the "secret zero" problem, and it's
inherent to KeePass itself, not something this integration can design
around. To keep that credential out of config.yaml too:

  - By default, the agent prompts for the master password interactively at
    startup (via getpass — it's never echoed, never logged, never written
    to disk). Fine for running the agent in a foreground terminal, which is
    how this project runs today.
  - If you need the agent to start unattended (e.g. as a background
    service), set the KEEPASS_MASTER_PASSWORD environment variable instead
    of a config.yaml field — same reasoning as the CrowdStrike/Tanium/etc.
    credentials: an env var set in your shell/service manager, never
    committed, never sitting in a config file someone might screenshot or
    share.
  - A key file (`keyfile_path` in config) is also supported and can be used
    instead of, or alongside, a master password, if that's how your
    database is set up.

Required config (under `secrets_backends.keepass`):
  database_path    path to your .kdbx file
  keyfile_path     optional, path to a key file if your database uses one

Setup: open your database in KeePass, add a new entry for each credential,
set its Title to the exact reference name you use in config.yaml (e.g.
"anthropic-api-key"), and put the real value in the Password field.
"""

import os
import getpass
import logging

from .base import SecretsProvider, SecretNotFoundError


class KeePassProvider(SecretsProvider):

    def __init__(self, database_path: str, keyfile_path: str = None):
        try:
            from pykeepass import PyKeePass
            from pykeepass.exceptions import CredentialsError
        except ImportError:
            raise RuntimeError(
                "pykeepass is required for the KeePass secrets backend. Install it with: "
                "pip install pykeepass"
            )

        self.database_path = database_path

        # Master password: environment variable first (for unattended/service
        # use), otherwise prompt interactively. Never read from config.yaml —
        # that would just move the hardcoding problem one level down.
        password = os.environ.get("KEEPASS_MASTER_PASSWORD")
        if not password:
            password = getpass.getpass(f"Enter KeePass master password to unlock {database_path}: ")

        try:
            self.kp = PyKeePass(database_path, password=password, keyfile=keyfile_path)
        except CredentialsError:
            raise RuntimeError(
                f"Could not unlock KeePass database at '{database_path}' — incorrect master "
                f"password or key file."
            )
        finally:
            # Don't keep the plaintext password sitting around in memory longer than needed.
            del password

        self._cache = {}
        logging.info(f"KeePass secrets backend active — database: {database_path}")

    def get(self, name: str) -> str:
        if name in self._cache:
            return self._cache[name]

        entry = self.kp.find_entries(title=name, first=True)
        if entry is None:
            raise SecretNotFoundError(
                f"No KeePass entry titled '{name}' found in '{self.database_path}'. Add an entry "
                f"with this exact title and put the real value in its Password field."
            )
        if not entry.password:
            raise SecretNotFoundError(
                f"KeePass entry '{name}' exists but has an empty Password field."
            )

        self._cache[name] = entry.password
        return entry.password
