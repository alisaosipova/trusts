"""Integration tests for the IPA global catalog listener.

The test-suite currently exercises the plumbing that makes the listener
available.  Real Windows interoperability checks will be hooked in once the
plugin exposes the required attribute projections.
"""

import pytest

pytestmark = [
    pytest.mark.skip("Global catalog listener requires follow-up implementation"),
]


def test_global_catalog_placeholder():
    """Placeholder test so pytest collects the module."""
    assert True
