"""Narrow, scope-confined tools the verification agent is wired to (VER-017)."""

from __future__ import annotations

from .http import GuardedHttpClient, ScopeViolation, same_origin, strip_cross_origin_auth

__all__ = ["GuardedHttpClient", "ScopeViolation", "same_origin", "strip_cross_origin_auth"]
