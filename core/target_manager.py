"""Target Registry — named, managed scan targets.

Replaces the old flow where a raw string was typed on every scan. A target
is validated once at registration, then referenced by name afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass

from database.database import Database
from database.repository import RepositoryError, TargetRepository
from security.authorization import Authorizer, TargetNotAllowedError
from security.targets import validate_target


@dataclass(frozen=True)
class TargetView:
    name: str
    value: str
    group: str | None


class TargetRegistry:
    def __init__(self, database: Database, authorizer: Authorizer | None = None) -> None:
        self._db = database
        self._authz = authorizer or Authorizer()

    def add(self, name: str, value: str, group: str | None = None) -> TargetView:
        name = (name or "").strip()
        if not name:
            raise ValueError("Target name is required.")
        if len(name) > 64:
            raise ValueError("Target name is too long (max 64 characters).")
        if any(c.isspace() for c in name):
            raise ValueError("Target name may not contain spaces.")

        # Validation AND scope restriction happen at registration time.
        validated = self._authz.assert_target_permitted(value)

        with self._db.session() as session:
            row = TargetRepository(session).add(
                name=name, value=validated, group_name=group
            )
            return TargetView(name=row.name, value=row.value, group=row.group_name)

    def get(self, name: str) -> TargetView | None:
        with self._db.session() as session:
            row = TargetRepository(session).get_by_name(name.strip())
            if row is None:
                return None
            return TargetView(name=row.name, value=row.value, group=row.group_name)

    def delete(self, name: str) -> bool:
        """Delete a target that has no scan history.

        Raises RepositoryError when history exists — the block-by-default
        policy. Never lets SQLAlchemy null out scans.target_id.
        """
        with self._db.session() as session:
            return TargetRepository(session).delete(name.strip())

    def history_count(self, name: str) -> dict[str, int]:
        """Counts a purge would remove, for the confirmation prompt."""
        with self._db.session() as session:
            repo = TargetRepository(session)
            row = repo.get_by_name(name.strip())
            if row is None:
                raise RepositoryError(f"No target named '{name}'.")
            return repo.pending_counts(row.id)

    def purge(self, name: str) -> dict[str, int]:
        """Delete a target and all its history. Irreversible."""
        with self._db.session() as session:
            return TargetRepository(session).purge(name.strip())

    def list(self) -> list[TargetView]:
        with self._db.session() as session:
            return [
                TargetView(name=r.name, value=r.value, group=r.group_name)
                for r in TargetRepository(session).list()
            ]

    def resolve(self, reference: str) -> TargetView | None:
        """Resolve either a registered name or a raw target string.

        Registered names win, so ``/scan lab`` works while
        ``/scan 8.8.8.8`` still behaves for ad-hoc use.
        """
        ref = (reference or "").strip()
        found = self.get(ref)
        if found is not None:
            return found
        try:
            validated = validate_target(ref)
        except ValueError:
            return None
        return TargetView(name=ref, value=validated, group=None)