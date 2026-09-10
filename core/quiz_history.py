"""Generic JSON-backed quiz-history store, shared by every quiz module.

Stores attempt summaries only (date, category, mode, score, total,
percentage) — never questions, answers, passwords, or other sensitive data.
"""
from __future__ import annotations

import json
from pathlib import Path

_REQUIRED_HISTORY_FIELDS = {"date", "category", "mode", "score", "total", "percentage"}


class QuizHistory:
    """Persists quiz-attempt summaries only, newest first, capped at MAX_ENTRIES."""

    MAX_ENTRIES = 20

    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        """Return recorded attempts (newest first), or an empty list on any failure."""
        try:
            entries = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(entries, list):
            return []
        valid = [entry for entry in entries if isinstance(entry, dict) and _REQUIRED_HISTORY_FIELDS <= set(entry)]
        return valid[: self.MAX_ENTRIES]

    def record(self, entry):
        """Prepend one attempt summary and keep at most MAX_ENTRIES. Never raises."""
        entries = [entry, *self.load()][: self.MAX_ENTRIES]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        except OSError:
            pass  # History is a convenience; a quiz must never crash when storage fails.
        return entries
