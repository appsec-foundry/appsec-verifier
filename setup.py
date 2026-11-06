"""Build the AppSec Verifier runtime, bundling its resources into the wheel.

Like AppSec Analyzer, the runtime resources (schemas/, data/) live at the repo
root for a source checkout, and are copied into the ``appsec_verifier`` package
at build time so a ``pipx install`` (which builds a wheel) carries them. The
package's ``resource_root()`` then finds them in either place.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
RUNTIME_DIRS = ("schemas", "data")

# Single source of the version — read without importing the package.
_version: dict = {}
exec((ROOT / "appsec_verifier" / "version_info.py").read_text(encoding="utf-8"), _version)  # noqa: S102
VERSION = _version["ENGINE_VERSION"]


class BuildVerifier(build_py):
    """Copy the runtime resource dirs into the built package."""

    def run(self) -> None:
        super().run()
        target = Path(self.build_lib) / "appsec_verifier"
        for name in RUNTIME_DIRS:
            src = ROOT / name
            if not src.is_dir():
                continue
            dst = target / name
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


setup(
    name="appsec-verifier",
    version=VERSION,
    description="Dynamic verification of static security-assessment findings against a running application.",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/appsec-foundry/appsec-verifier",
    license="Apache-2.0",
    python_requires=">=3.10",
    packages=find_packages(include=["appsec_verifier", "appsec_verifier.*"]),
    include_package_data=True,
    install_requires=[
        "PyYAML>=6.0",
        "jsonschema>=4.0",
    ],
    entry_points={"console_scripts": ["appsec-verifier=appsec_verifier.cli:main"]},
    cmdclass={"build_py": BuildVerifier},
)
