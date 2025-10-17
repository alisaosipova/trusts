# IPA Global Catalog plugin skeleton

This directory introduces scaffolding for the IPA Global Catalog listener.  The
implementation is intentionally small and focuses on delivering configuration
and documentation so that other components – namely the installer and test
suite – can depend on a stable file layout.

The actual 389 Directory Server plugin will be implemented in C similarly to
`ipa-extdom` and `ipa-compat`.  Until the C module lands the configuration file
below acts as a placeholder; it allows LDAP update templates to reference a
well-defined plugin entry without attempting to load a missing shared object.
