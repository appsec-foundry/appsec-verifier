"""AppSec Verifier: tests the findings of an AppSec Analyzer security assessment
against the running application and reports per finding whether the weakness
reproduces (requirements.md, docs/cli.md).
"""

from __future__ import annotations

from .version_info import ENGINE_VERSION, resource_root

__all__ = ["ENGINE_VERSION", "resource_root"]
