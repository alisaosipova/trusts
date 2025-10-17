"""Integration tests for the IPA global catalog listener."""

from __future__ import annotations

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

pytestmark = pytest.mark.tier1


class TestGlobalCatalog(IntegrationTest):
    """Validate that the global catalog listener exposes AD friendly data."""

    topology = "line"

    def _ldapsearch_gc(self, search_filter: str, *attrs: str) -> dict[str, list[str]]:
        cmd = [
            "ldapsearch",
            "-x",
            "-LLL",
            "-o",
            "ldif-wrap=no",
            "-H",
            f"ldap://{self.master.hostname}:3268",
            "-D",
            str(self.master.config.dirman_dn),
            "-w",
            self.master.config.dirman_password,
            "-b",
            str(self.master.domain.basedn),
            search_filter,
        ]
        cmd.extend(attrs)

        result = self.master.run_command(cmd)

        entry: dict[str, list[str]] = {}
        for raw_line in result.stdout_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                if entry:
                    break
                continue
            if ":" not in line:
                continue
            if "::" in line:
                key, value = line.split("::", 1)
                value = value.strip()
            else:
                key, value = line.split(":", 1)
                value = value.strip()
            entry.setdefault(key, []).append(value)
        return entry

    def test_admin_entry_in_global_catalog(self):
        """Ensure the administrator record exposes Windows attributes."""

        realm = self.master.domain.realm
        admin_entry = self._ldapsearch_gc(
            "(uid=admin)",
            "sAMAccountName",
            "userPrincipalName",
            "objectSid",
        )

        assert admin_entry.get("sAMAccountName") == ["admin"], admin_entry
        assert admin_entry.get("userPrincipalName") == [f"admin@{realm}"], admin_entry
        sid_values = admin_entry.get("objectSid", [])
        assert sid_values and sid_values[0].startswith("S-"), admin_entry

    def test_new_user_is_visible_in_global_catalog(self):
        """Create a fresh user and verify the GC provides the projected data."""

        username = "gcuser"
        password = "Secret.123"

        try:
            tasks.user_add(
                self.master,
                username,
                first="Global",
                last="Catalog",
                password=password,
            )

            entry = self._ldapsearch_gc(
                f"(uid={username})",
                "sAMAccountName",
                "userPrincipalName",
                "objectSid",
            )

            assert entry.get("sAMAccountName") == [username], entry
            assert entry.get("userPrincipalName") == [
                f"{username}@{self.master.domain.realm}"
            ], entry
            assert entry.get("objectSid"), entry
        finally:
            tasks.user_del(self.master, username)

    def test_global_catalog_service_help(self):
        """Ensure administrative tooling advertises the global catalog service."""

        result = self.master.run_command(["ipa", "help", "topics"])
        assert "global catalog" in result.stdout_text.lower(), result.stdout_text
