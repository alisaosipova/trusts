"""Integration tests for the IPA global catalog listener."""

from __future__ import annotations
import base64
from typing import Dict, List

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

pytestmark = pytest.mark.tier1


class TestGlobalCatalog(IntegrationTest):
    """Validate that the global catalog listener exposes AD friendly data."""

    topology = "line"

    @staticmethod
    def _sid_bytes_to_string(data: bytes) -> str:
        if len(data) < 8:
            raise ValueError("SID payload is too small")

        revision = data[0]
        subauth_count = data[1]
        identifier_authority = int.from_bytes(data[2:8], "big")
        offset = 8
        subauths: List[int] = []
        for _ in range(subauth_count):
            if offset + 4 > len(data):
                raise ValueError("SID payload truncated")
            subauths.append(int.from_bytes(data[offset:offset + 4], "little"))
            offset += 4

        trailer = "".join(f"-{value}" for value in subauths)
        return f"S-{revision}-{identifier_authority}{trailer}"

    def _ldapsearch_gc(self, search_filter: str, *attrs: str) -> Dict[str, List[str]]:
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

        entry: Dict[str, List[str]] = {}
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
                if key == "objectSid":
                    decoded = base64.b64decode(value)
                    value = self._sid_bytes_to_string(decoded)
            else:
                key, value = line.split(":", 1)
                value = value.strip()
            entry.setdefault(key, []).append(value)
        return entry

    def _ldapsearch(self, base_dn: str, search_filter: str, *attrs: str) -> Dict[str, List[str]]:
        cmd = [
            "ldapsearch",
            "-x",
            "-LLL",
            "-o",
            "ldif-wrap=no",
            "-H",
            f"ldap://{self.master.hostname}",
            "-D",
            str(self.master.config.dirman_dn),
            "-w",
            self.master.config.dirman_password,
            "-b",
            base_dn,
            search_filter,
        ]
        cmd.extend(attrs)

        result = self.master.run_command(cmd)

        entry: Dict[str, List[str]] = {}
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
                value = base64.b64decode(value.strip()).decode()
            else:
                key, value = line.split(":", 1)
                value = value.strip()
            entry.setdefault(key, []).append(value)
        return entry

    def _fallback_primary_group(self) -> str:
        domain_entry = self._ldapsearch(
            str(self.master.domain.basedn),
            "(objectClass=ipaNTDomainAttrs)",
            "ipaNTFallbackPrimaryGroup",
        )
        fallback_dn = domain_entry.get("ipaNTFallbackPrimaryGroup")
        if not fallback_dn:
            raise RuntimeError("Fallback primary group is not configured")

        group_entry = self._ldapsearch(
            fallback_dn[0],
            "(objectClass=*)",
            "ipaNTSecurityIdentifier",
        )
        sid_values = group_entry.get("ipaNTSecurityIdentifier")
        if not sid_values:
            raise RuntimeError("Fallback primary group SID is not available")

        sid = sid_values[0]
        try:
            return sid.rsplit("-", 1)[1]
        except (IndexError, ValueError) as exc:
            raise RuntimeError("Malformed SID for fallback primary group") from exc

    def test_admin_entry_in_global_catalog(self):
        """Ensure the administrator record exposes Windows attributes."""

        realm = self.master.domain.realm
        admin_entry = self._ldapsearch_gc(
            "(uid=admin)",
            "sAMAccountName",
            "userPrincipalName",
            "objectSid",
            "objectClass",
            "primaryGroupID",
        )

        assert admin_entry.get("sAMAccountName") == ["admin"], admin_entry
        assert admin_entry.get("userPrincipalName") == [f"admin@{realm}"], admin_entry
        sid_values = admin_entry.get("objectSid", [])
        assert sid_values and sid_values[0].startswith("S-"), admin_entry
        object_classes = {value.lower() for value in admin_entry.get("objectClass", [])}
        assert "user" in object_classes, admin_entry
        assert admin_entry.get("primaryGroupID") == [self._fallback_primary_group()], admin_entry

    def test_new_user_is_visible_in_global_catalog(self):
        """Create a fresh user and verify the GC provides the projected data."""

        username = "gcuser"
        groupname = "gcgroup"
        parent_groupname = "gcparent"
        password = "Secret.123"

        try:
            tasks.user_add(
                self.master,
                username,
                first="Global",
                last="Catalog",
                password=password,
            )

            tasks.group_add(self.master, groupname)
            tasks.group_add_member(self.master, groupname, username)

            tasks.group_add(self.master, parent_groupname)
            tasks.group_add_member(
                self.master,
                parent_groupname,
                extra_args=("--groups", groupname),
            )

            entry = self._ldapsearch_gc(
                f"(uid={username})",
                "sAMAccountName",
                "userPrincipalName",
                "objectSid",
                "objectClass",
                "primaryGroupID",
                "memberOf",
            )

            assert entry.get("sAMAccountName") == [username], entry
            assert entry.get("userPrincipalName") == [
                f"{username}@{self.master.domain.realm}"
            ], entry
            assert entry.get("objectSid"), entry

            object_classes = {value.lower() for value in entry.get("objectClass", [])}
            assert "user" in object_classes, entry
            assert entry.get("primaryGroupID") == [self._fallback_primary_group()], entry

            user_dn = f"uid={username},cn=users,cn=accounts,{self.master.domain.basedn}"
            group_dn = f"cn={groupname},cn=groups,cn=accounts,{self.master.domain.basedn}"
            member_of = {value.lower() for value in entry.get("memberOf", [])}
            assert group_dn.lower() in member_of, entry

            group_entry = self._ldapsearch_gc(
                f"(cn={groupname})",
                "sAMAccountName",
                "objectSid",
                "objectClass",
                "groupType",
                "member",
                "memberOf",
            )

            assert group_entry.get("sAMAccountName") == [groupname], group_entry
            assert group_entry.get("objectSid"), group_entry
            group_classes = {value.lower() for value in group_entry.get("objectClass", [])}
            assert "group" in group_classes, group_entry
            assert group_entry.get("groupType") == ["-2147483646"], group_entry
            members = {value.lower() for value in group_entry.get("member", [])}
            assert user_dn.lower() in members, group_entry

            parent_dn = (
                f"cn={parent_groupname},cn=groups,cn=accounts," f"{self.master.domain.basedn}"
            )
            member_of_groups = {value.lower() for value in group_entry.get("memberOf", [])}
            assert parent_dn.lower() in member_of_groups, group_entry

            parent_entry = self._ldapsearch_gc(
                f"(cn={parent_groupname})",
                "groupType",
                "member",
            )

            assert parent_entry.get("groupType") == ["-2147483646"], parent_entry
            parent_members = {value.lower() for value in parent_entry.get("member", [])}
            assert group_dn.lower() in parent_members, parent_entry
        finally:
            try:
                self.master.run_command(
                    [
                        "ipa",
                        "group-remove-member",
                        parent_groupname,
                        "--groups",
                        groupname,
                    ],
                    raiseonerr=False,
                )
            except Exception:
                pass
            try:
                tasks.group_del(self.master, parent_groupname)
            except Exception:
                pass
            try:
                tasks.group_del(self.master, groupname)
            except Exception:
                pass
            tasks.user_del(self.master, username)

    def test_global_catalog_service_help(self):
        """Ensure administrative tooling advertises the global catalog service."""

        result = self.master.run_command(["ipa", "help", "topics"])
        assert "global catalog" in result.stdout_text.lower(), result.stdout_text
