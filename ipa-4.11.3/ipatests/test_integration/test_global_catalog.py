"""Integration tests for the IPA global catalog listener."""

from __future__ import annotations

import base64
import re
import textwrap

import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestGlobalCatalogListener(IntegrationTest):
    """Validate that CLDAP accurately reflects the GC listener state."""

    topology = "line"
    num_replicas = 0
    num_clients = 0

    GC_PLUGIN_DN = "cn=ipa-globalcatalog,cn=plugins,cn=config"
    GC_MARKER_PREFIX = "listener="
    GC_MARKER_ENABLED = "listener=enabled"
    GC_MARKER_DISABLED = "listener=disabled"
    GC_PORT = 3268
    NBT_SERVER_GC = 0x00000004

    @classmethod
    def install(cls, mh):
        super().install(mh)
        tasks.install_adtrust(cls.master)

        cls.gc_config_dn = (
            f"cn=global catalog,cn=ipa,cn=etc,{cls.master.domain.basedn}"
        )
        cls.original_gc_config = cls._get_gc_config_strings()
        cls.original_plugin_enabled = cls._is_gc_plugin_enabled()

        cls._set_gc_state(False)

    @classmethod
    def teardown_class(cls):
        try:
            cls._set_gc_state(cls.original_plugin_enabled)
            cls._set_gc_config_strings(cls.original_gc_config)
        finally:
            super().teardown_class()

    def test_cldap_gc_advertisement_tracks_listener(self):
        """CLDAP advertises GC availability only when the listener is up."""

        # Ensure the disabled state does not advertise a GC endpoint.
        self._set_gc_state(False)
        server_type = self._query_netlogon_server_type()
        assert (server_type & self.NBT_SERVER_GC) == 0

        # Enable the listener and confirm both the flag and the service respond.
        self._set_gc_state(True)
        server_type = self._query_netlogon_server_type()
        assert server_type & self.NBT_SERVER_GC
        self._assert_gc_port_responds()

    @classmethod
    def _set_gc_state(cls, enabled: bool) -> None:
        marker = cls.GC_MARKER_ENABLED if enabled else cls.GC_MARKER_DISABLED
        values = [
            v
            for v in cls._get_gc_config_strings()
            if not v.startswith(cls.GC_MARKER_PREFIX)
        ]
        values.append(marker)
        cls._set_gc_config_strings(values)

        if cls._is_gc_plugin_enabled() != enabled:
            cls._set_plugin_enabled(enabled)
            cls._restart_ipa_services()
        if enabled:
            cls._wait_for_gc_listener()

    @classmethod
    def _get_gc_config_strings(cls) -> list[str]:
        result = tasks.ldapsearch_dm(
            cls.master,
            cls.gc_config_dn,
            ["(objectClass=*)", "ipaConfigString"],
            scope="base",
        )
        return [
            line.split(":", 1)[1].strip()
            for line in result.stdout_text.splitlines()
            if line.startswith("ipaConfigString:")
        ]

    @classmethod
    def _set_gc_config_strings(cls, values: list[str]) -> None:
        if values:
            body = "".join(f"ipaConfigString: {value}\n" for value in values)
            ldif = textwrap.dedent(
                f"""\
                dn: {cls.gc_config_dn}
                changetype: modify
                replace: ipaConfigString
                {body}"""
            )
            tasks.ldapmodify_dm(cls.master, ldif)
        else:
            ldif = textwrap.dedent(
                f"""\
                dn: {cls.gc_config_dn}
                changetype: modify
                delete: ipaConfigString
                """
            )
            tasks.ldapmodify_dm(cls.master, ldif, ok_returncode=[0, 16])

    @classmethod
    def _is_gc_plugin_enabled(cls) -> bool:
        result = tasks.ldapsearch_dm(
            cls.master,
            cls.GC_PLUGIN_DN,
            ["(objectClass=*)", "nsslapd-pluginEnabled"],
            scope="base",
        )
        for line in result.stdout_text.splitlines():
            if line.startswith("nsslapd-pluginEnabled:"):
                return line.split(":", 1)[1].strip().lower() == "on"
        return False

    @classmethod
    def _set_plugin_enabled(cls, enabled: bool) -> None:
        value = "on" if enabled else "off"
        ldif = textwrap.dedent(
            f"""\
            dn: {cls.GC_PLUGIN_DN}
            changetype: modify
            replace: nsslapd-pluginEnabled
            nsslapd-pluginEnabled: {value}
            """
        )
        tasks.ldapmodify_dm(cls.master, ldif)

    @classmethod
    def _restart_ipa_services(cls) -> None:
        cls.master.run_command(["ipactl", "restart"])
        tasks.wait_for_ipa_to_start(cls.master)

    @classmethod
    def _wait_for_gc_listener(cls, timeout: int = 60) -> None:
        script = textwrap.dedent(
            f"""\
            import socket
            import time

            deadline = time.time() + {timeout}
            while time.time() < deadline:
                try:
                    with socket.create_connection(("{cls.master.hostname}", {cls.GC_PORT}), 1):
                        raise SystemExit(0)
                except OSError:
                    time.sleep(1)
            raise SystemExit(1)
            """
        )
        cls.master.run_command(["python3", "-c", script])

    def _query_netlogon_server_type(self) -> int:
        filter_expr = (
            "(&"
            f"(DnsDomain={self.master.domain.name})"
            "(NtVer=\\06\\00\\00\\00)"
            "(AAC=\\00\\00\\00\\00)"
            ")"
        )
        result = self.master.run_command(
            [
                "ldapsearch",
                "-LLL",
                "-o",
                "ldif-wrap=no",
                "-H",
                f"cldap://{self.master.hostname}",
                "-b",
                "",
                "-s",
                "base",
                filter_expr,
                "netlogon",
            ]
        )

        match = re.search(r"^netlogon:: ([A-Za-z0-9+/=]+)$", result.stdout_text, re.MULTILINE)
        if not match:
            pytest.fail("Netlogon attribute missing from CLDAP response")

        blob_b64 = match.group(1)
        script = textwrap.dedent(
            """\
            import base64
            import sys

            try:
                from samba.dcerpc import nbt
                from samba.ndr import ndr_unpack
            except ModuleNotFoundError as exc:
                print(exc, file=sys.stderr)
                raise SystemExit(2)

            data = base64.b64decode(sys.stdin.read())
            reply = ndr_unpack(nbt.NETLOGON_SAM_LOGON_RESPONSE_EX, data)
            print(reply.server_type)
            """
        )
        decode = self.master.run_command(
            ["python3", "-c", script], stdin_text=blob_b64, raiseonerr=False
        )
        if decode.returncode == 2:
            pytest.skip("Samba python bindings are required to decode NETLOGON blobs")
        if decode.returncode != 0:
            pytest.fail(
                "Failed to decode NETLOGON response: {}".format(
                    decode.stderr_text.strip()
                )
            )
        return int(decode.stdout_text.strip())

    def _assert_gc_port_responds(self) -> None:
        result = self.master.run_command(
            [
                "ldapsearch",
                "-LLL",
                "-x",
                "-o",
                "ldif-wrap=no",
                "-H",
                f"ldap://{self.master.hostname}:{self.GC_PORT}",
                "-b",
                str(self.master.domain.basedn),
                "-s",
                "base",
                "(objectClass=*)",
                "cn",
            ]
        )
        assert "dn:" in result.stdout_text
