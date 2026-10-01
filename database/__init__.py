"""Persistence layer: models, repository, engine.

Milestone 3. PostgreSQL via SQLAlchemy. The Repository pattern keeps SQL
behind an interface so the rest of the code depends on repositories, not
on the ORM — which also makes the change detector easy to unit-test.
"""

from __future__ import annotations
