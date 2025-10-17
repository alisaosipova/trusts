"""Global Catalog provisioning helpers.

This module provides a very small management surface that allows
ipa-adtrust-install to prepare a read-only LDAP listener that mimics the
behaviour of an Active Directory Global Catalog.  The real heavy lifting is
performed by the 389-DS plugin shipped in ``daemons/ipa-slapi-plugins``.  The
python side focuses on configuration management so that installers and test
suites can enable the service in a predictable way.

At the moment the implementation intentionally keeps the public API narrow:

``GlobalCatalogInstance``
    Helper exposing ``configure()``, ``enable()`` and ``replicate()`` hooks used
    by ``ipaserver.install.adtrustinstance``.

The helper defers all LDAP modifications to ``ldapupdate`` templates located in
``install/updates`` which keeps the file modifications idempotent and friendly
for replica deployments.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from ipapython import ipautil
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


class GlobalCatalogInstance:
    """Drive configuration for the IPA global catalog listener.

    The helper is intentionally light-weight – it does not attempt to talk to
    LDAP directly.  Instead it relies on ``ldapupdate`` templates that are
    shipped alongside the 389-DS plugin and applies them by invoking the
    standard ``ipa-ldap-updater`` wrapper.

    The goal is to provide a thin abstraction layer that ``ipa-adtrust-install``
    and replica installers can use while keeping the heavy lifting in easily
    testable LDIF templates.
    """

    UPDATE_TEMPLATE = "60-global-catalog.ldif"
    PLUGIN_TEMPLATE = "global-catalog-conf.ldif"

    def __init__(
        self,
        instance_name: str | None,
        update_dir: Path | str,
        data_dir: Path | str | None = None,
    ) -> None:
        self.instance_name = instance_name
        self.update_dir = Path(update_dir)
        if data_dir is None:
            data_dir = paths.IPA_DATA_DIR
        self.data_dir = Path(data_dir)

    @property
    def update_files(self) -> Iterable[Path]:
        """Return the LDIF snippets required for the GC service."""
        update_file = self.update_dir / self.UPDATE_TEMPLATE
        plugin_file = self.data_dir / self.PLUGIN_TEMPLATE

        files: list[Path] = []

        if update_file.exists():
            files.append(update_file)
        else:
            logger.debug(
                "Global catalog template %s is not present; GC remains disabled",
                update_file,
            )

        if plugin_file.exists():
            files.append(plugin_file)
        else:
            logger.debug(
                "Global catalog plugin template %s is missing", plugin_file
            )

        return files

    def _run_updater(self, files: Iterable[Path]) -> None:
        if not files:
            logger.info(
                "Skipping global catalog configuration – no update templates were found"
            )
            return

        paths = [str(p) for p in files]
        logger.debug("Applying global catalog updates: %s", ", ".join(paths))
        cmd = ["ipa-ldap-updater", "--validate", *paths]
        if self.instance_name:
            cmd.extend(["--service", self.instance_name])
        ipautil.run(cmd)

    def configure(self) -> None:
        """Ensure GC schema and plugin configuration are present."""
        logger.info("Configuring IPA global catalog service")
        self._run_updater(self.update_files)

    def enable(self) -> None:
        """Enable the listener in case it is delivered in a disabled state."""
        logger.info("Global catalog listener is managed by the LDAP template; no-op")

    def replicate(self) -> None:
        """Trigger replica-specific configuration steps."""
        logger.info("Replica global catalog configuration uses the same templates")
        self.configure()
