import re

from packaging.utils import InvalidName, canonicalize_name, canonicalize_version
from packaging.version import InvalidVersion
from packaging.version import Version as PythonVersion
from semver import Version as NpmVersion

from .models import Ecosystem

_NPM_NAME = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]*", re.ASCII)


def package_name(ecosystem: Ecosystem, value: str) -> str | None:
    if len(value) > 214:
        return None
    if ecosystem == Ecosystem.NPM:
        # npm identities use explicit, already lowercase names. Do not silently repair case.
        return value if _NPM_NAME.fullmatch(value) else None
    try:
        return canonicalize_name(value, validate=True)
    except InvalidName:
        return None


def ordered_version(ecosystem: Ecosystem, value: str) -> PythonVersion | NpmVersion | None:
    if not value or len(value) > 128:
        return None
    try:
        return PythonVersion(value) if ecosystem == Ecosystem.PYPI else NpmVersion.parse(value)
    except (InvalidVersion, ValueError):
        return None


def exact_version(ecosystem: Ecosystem, value: str) -> str | None:
    version = ordered_version(ecosystem, value)
    if version is None:
        return None
    if isinstance(version, PythonVersion):
        return canonicalize_version(version)
    return str(version)
