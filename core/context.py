"""Application-wide, immutable startup state."""
from dataclasses import dataclass


@dataclass(frozen=True)
class AppContext:
    is_admin: bool
    app_version: str
