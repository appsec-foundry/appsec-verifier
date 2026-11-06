"""AppSec Verifier — dynamic verification of static security-assessment findings.

Design-stage package: `scope` and `plan` run offline today; `verify` and
`export` are specified (see requirements.md, docs/cli.md) but not implemented.
"""

from __future__ import annotations

from .version_info import ENGINE_VERSION, resource_root

__all__ = ["ENGINE_VERSION", "resource_root"]
