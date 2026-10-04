"""Repository pattern — SQL lives here and nowhere else.

Callers depend on these classes, never on the ORM directly, so the change
detector and scan manager can be unit-tested against an in-memory SQLite
database with no stubbing.
"""

from __future__ import annotations

from dataclasses import dataclass

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from core.rule_values import validate_value
from database.models import (
    ChangeEvent,
    Host,
    OperatorChat,
    Rule,
    RuleHit,
    Scan,
    Schedule,
    Service,
    Target,
)


class RepositoryError(RuntimeError):
    """Raised for policy violations that callers should surface to the user.

    These carry messages meant to be shown verbatim in chat, so they stay
    human-readable rather than leaking SQLAlchemy internals.
    """


def _utcnow() -> datetime:
    """Naive UTC, matching how timestamps are stored server-side."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def add(self, name: str, value: str, group_name: str | None = None) -> Target:
        if self.get_by_name(name) is not None:
            raise RepositoryError(f"Target '{name}' already exists.")
        target = Target(name=name, value=value, group_name=group_name)
        self._s.add(target)
        self._s.flush()
        return target

    def get_by_name(self, name: str) -> Target | None:
        return self._s.scalar(select(Target).where(Target.name == name))

    def get(self, target_id: int) -> Target | None:
        return self._s.get(Target, target_id)

    def scan_count(self, target_id: int) -> int:
        return int(
            self._s.scalar(
                select(func.count())
                .select_from(Scan)
                .where(Scan.target_id == target_id)
            )
            or 0
        )

    def pending_counts(self, target_id: int) -> dict[str, int]:
        """Row counts a purge would remove — for the confirmation prompt."""
        scan_count = self.scan_count(target_id)
        host_count = 0
        service_count = 0
        change_count = 0
        if scan_count:
            scan_ids = list(
                self._s.scalars(select(Scan.id).where(Scan.target_id == target_id))
            )
            host_ids = list(
                self._s.scalars(select(Host.id).where(Host.scan_id.in_(scan_ids)))
            )
            host_count = len(host_ids)
            if host_ids:
                service_count = int(
                    self._s.scalar(
                        select(func.count())
                        .select_from(Service)
                        .where(Service.host_id.in_(host_ids))
                    )
                    or 0
                )
            change_count = int(
                self._s.scalar(
                    select(func.count())
                    .select_from(ChangeEvent)
                    .where(ChangeEvent.scan_id.in_(scan_ids))
                )
                or 0
            )
        return {
            "targets": 1,
            "scans": scan_count,
            "hosts": host_count,
            "services": service_count,
            "change_events": change_count,
            "schedules": int(
                self._s.scalar(
                    select(func.count())
                    .select_from(Schedule)
                    .where(Schedule.target_id == target_id)
                )
                or 0
            ),
        }

    def delete(self, name: str) -> bool:
        """Delete a target that has no scan history.

        Block-by-default: a target that any scan references is refused, so
        security history cannot be destroyed by a single command.

        The dependency check must happen *before* the delete. SQLAlchemy's
        default for an unloaded parent->child relationship is to null out
        the child's foreign key first, which emits
        ``UPDATE scans SET target_id = NULL`` and trips the NOT NULL
        constraint. Checking first means that UPDATE is never attempted.
        """
        target = self.get_by_name(name)
        if target is None:
            return False

        count = self.scan_count(target.id)
        if count:
            raise RepositoryError(
                f"Cannot delete target '{name}': {count} scan(s) reference it. "
                f"Use /purge {name} confirm to delete the target and its history."
            )

        self._s.delete(target)
        self._s.flush()
        return True

    def purge_by_id(self, target_id: int) -> dict[str, int]:
        """Purge by primary key rather than name — used by the admin panel.

        Identical policy to :meth:`purge`; this exists because the panel
        works with row ids, not names.
        """
        target = self.get(target_id)
        if target is None:
            raise RepositoryError(f"No target with id {target_id}.")

        scan_ids = list(
            self._s.scalars(select(Scan.id).where(Scan.target_id == target.id))
        )
        host_ids: list[int] = []
        if scan_ids:
            host_ids = list(
                self._s.scalars(
                    select(Host.id).where(Host.scan_id.in_(scan_ids))
                )
            )

        counts = {"services": 0, "hosts": 0, "change_events": 0, "scans": 0}
        counts["schedules"] = self._s.execute(
            delete(Schedule).where(Schedule.target_id == target.id)
        ).rowcount
        if host_ids:
            counts["services"] = self._s.execute(
                delete(Service).where(Service.host_id.in_(host_ids))
            ).rowcount
        if scan_ids:
            counts["change_events"] = self._s.execute(
                delete(ChangeEvent).where(ChangeEvent.scan_id.in_(scan_ids))
            ).rowcount
            counts["hosts"] = self._s.execute(
                delete(Host).where(Host.id.in_(host_ids))
            ).rowcount
            counts["scans"] = self._s.execute(
                delete(Scan).where(Scan.id.in_(scan_ids))
            ).rowcount

        self._s.delete(target)
        self._s.flush()
        counts["targets"] = 1
        return counts

    def purge(self, name: str) -> dict[str, int]:
        """Delete a target and all of its history, in safe FK order.

        Returns the number of rows removed per table. Children first:
        services -> hosts -> change_events -> scans -> schedules -> target.
        """
        target = self.get_by_name(name)
        if target is None:
            raise RepositoryError(f"No target named '{name}'.")

        scan_ids = list(
            self._s.scalars(select(Scan.id).where(Scan.target_id == target.id))
        )
        host_ids: list[int] = []
        if scan_ids:
            host_ids = list(
                self._s.scalars(
                    select(Host.id).where(Host.scan_id.in_(scan_ids))
                )
            )

        counts = {"services": 0, "hosts": 0, "change_events": 0, "scans": 0}
        counts["schedules"] = self._s.execute(
            delete(Schedule).where(Schedule.target_id == target.id)
        ).rowcount
        if host_ids:
            counts["services"] = self._s.execute(
                delete(Service).where(Service.host_id.in_(host_ids))
            ).rowcount
        if scan_ids:
            counts["change_events"] = self._s.execute(
                delete(ChangeEvent).where(ChangeEvent.scan_id.in_(scan_ids))
            ).rowcount
            counts["hosts"] = self._s.execute(
                delete(Host).where(Host.id.in_(host_ids))
            ).rowcount
            counts["scans"] = self._s.execute(
                delete(Scan).where(Scan.id.in_(scan_ids))
            ).rowcount

        self._s.delete(target)
        self._s.flush()
        counts["targets"] = 1
        return counts

    def get_or_create_by_value(self, value: str) -> Target:
        """Find a target by its scan value, creating an implicit one if needed.

        Lets ad-hoc values (``/scan 8.8.8.8``) still get a row, so every
        scan has a valid foreign key and history stays queryable per target.

        Two scan worker threads can race on the same unseen value: both read
        "not found", both insert, and the unique index on ``name`` rejects
        the loser. The insert therefore runs inside a SAVEPOINT so a lost
        race can be rolled back and retried as a plain read, instead of
        poisoning the caller's whole transaction.
        """
        row = self._s.scalar(select(Target).where(Target.value == value))
        if row is not None:
            return row

        name = value
        if self.get_by_name(name) is not None:
            # Name collision with an explicit target: suffix deterministically.
            suffix = 1
            while self.get_by_name(f"{value}#{suffix}") is not None:
                suffix += 1
            name = f"{value}#{suffix}"

        savepoint = self._s.begin_nested()
        try:
            row = Target(name=name, value=value, group_name=None, enabled=1)
            self._s.add(row)
            self._s.flush()
        except IntegrityError:
            # Lost the race, or another row claimed the name meanwhile.
            savepoint.rollback()
            existing = self._s.scalar(
                select(Target).where(Target.value == value)
            )
            if existing is not None:
                return existing
            # The value is absent but the name is taken: fall back to a
            # suffixed name and try once more.
            suffix = 1
            while self.get_by_name(f"{value}#{suffix}") is not None:
                suffix += 1
            row = Target(
                name=f"{value}#{suffix}", value=value, group_name=None, enabled=1
            )
            self._s.add(row)
            self._s.flush()
        return row

    def list(self) -> list[Target]:
        return list(self._s.scalars(select(Target).order_by(Target.name)))


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def create(
        self,
        target_id: int,
        profile: str,
        source: str = "manual",
        requested_by: int | None = None,
    ) -> Scan:
        scan = Scan(
            target_id=target_id,
            profile=profile,
            status="running",
            source=source,
            requested_by=requested_by,
        )
        self._s.add(scan)
        self._s.flush()
        return scan

    def get(self, scan_id: int) -> Scan | None:
        return self._s.scalar(
            select(Scan).where(Scan.id == scan_id).options(
                joinedload(Scan.target),
                joinedload(Scan.hosts).joinedload(Host.services),
            )
        )

    def latest_succeeded(
        self, target_id: int, profile: str, exclude_id: int | None = None
    ) -> Scan | None:
        """Most recent successful scan of this target+profile — the baseline.

        ``target`` is eager-loaded alongside hosts/services: callers keep
        these rows after the session closes, and a lazy relationship would
        raise DetachedInstanceError on access.
        """
        stmt = (
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.profile == profile,
                Scan.status == "succeeded",
            )
            .options(
                joinedload(Scan.target),
                joinedload(Scan.hosts).joinedload(Host.services),
            )
            .order_by(desc(Scan.id))
        )
        if exclude_id is not None:
            stmt = stmt.where(Scan.id != exclude_id)
        return self._s.scalars(stmt.limit(1)).unique().first()

    def recent(self, target_id: int, limit: int = 10) -> list[Scan]:
        """Most recent scans for a target.

        ``target``, ``hosts`` and ``services`` are all eager-loaded, because
        these rows are consumed *after* the session closes:

        * the message formatter reads ``s.target.name``;
        * the exporter walks ``scan.hosts[].services[]``.

        Any relationship left lazy raises DetachedInstanceError there, which
        is exactly the bug this eager-loading prevents.
        """
        return list(
            self._s.scalars(
                select(Scan)
                .where(Scan.target_id == target_id)
                .options(
                    joinedload(Scan.target),
                    joinedload(Scan.hosts).joinedload(Host.services),
                )
                .order_by(desc(Scan.id))
                .limit(limit)
            ).unique()
        )

    def last_successful_per_target(self) -> list[Scan]:
        """Newest succeeded scan for every target — for /health."""
        subq = (
            select(
                Scan.target_id,
                func.max(Scan.finished_at).label("last_finished"),
            )
            .where(Scan.status == "succeeded")
            .group_by(Scan.target_id)
            .subquery()
        )
        return list(
            self._s.scalars(
                select(Scan)
                .join(
                    subq,
                    (Scan.target_id == subq.c.target_id)
                    & (Scan.finished_at == subq.c.last_finished),
                )
                .options(joinedload(Scan.target))
                .order_by(Scan.target_id)
            ).unique()
        )

    def in_window(
        self, target_id: int, days: int, limit: int | None = None
    ) -> list[Scan]:
        """Scans started within the last ``days`` days, newest first.

        Eager-loads target, hosts and services so callers can render after
        the session closes.
        """
        cutoff = _utcnow() - timedelta(days=days)
        stmt = (
            select(Scan)
            .where(Scan.target_id == target_id, Scan.started_at >= cutoff)
            .options(
                joinedload(Scan.target),
                joinedload(Scan.hosts).joinedload(Host.services),
            )
            .order_by(desc(Scan.id))
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._s.scalars(stmt).unique())

    def complete(
        self,
        scan: Scan,
        *,
        host_count: int,
        service_count: int,
        duration_ms: int,
        error: str | None = None,
    ) -> None:
        scan.status = "failed" if error else "succeeded"
        scan.host_count = host_count
        scan.service_count = service_count
        scan.duration_ms = duration_ms
        scan.error = error
        scan.finished_at = _utcnow()
        self._s.flush()

    def store_snapshot(
        self, scan: Scan, hosts: list[dict], services_by_host: dict[str, list[dict]]
    ) -> None:
        """Persist a normalized snapshot into Host/Service rows."""
        for h in hosts:
            host = Host(
                scan_id=scan.id,
                address=h["address"],
                hostname=h.get("hostname"),
                state=h.get("state", "up"),
            )
            self._s.add(host)
            self._s.flush()
            for svc in services_by_host.get(h["address"], []):
                self._s.add(
                    Service(
                        host_id=host.id,
                        port=svc["port"],
                        protocol=svc.get("protocol", "tcp"),
                        state=svc.get("state", "open"),
                        service_name=svc.get("service_name"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                    )
                )
        self._s.flush()

    def count_since(self, user_id: int, cutoff: datetime) -> int:
        """Scans started by ``user_id`` at or after ``cutoff``.

        Backs the ``user_quota`` rule, which counts scans per hour or
        per day. ``requested_by`` is indexed-friendly here because it
        doubles as the actor filter for quota accounting.
        """
        return int(
            self._s.scalar(
                select(func.count())
                .select_from(Scan)
                .where(
                    Scan.requested_by == user_id,
                    Scan.started_at >= cutoff,
                )
            )
            or 0
        )

    def latest_started_for_target_name(self, target_name: str) -> datetime | None:
        """When this target was last scanned, by name.

        The rate limiter keys on target *name*, so the rule context has
        to match: a rule limiting a target must see the same history the
        limiter sees.
        """
        return self._s.scalar(
            select(Scan.started_at)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.name == target_name)
            .order_by(desc(Scan.started_at))
            .limit(1)
        )

    # ---- retention (V1) -------------------------------------------
    def deletable_ids(
        self,
        target_id: int,
        *,
        keep_days: int,
        keep_per_target: int,
    ) -> list[int]:
        """IDs a retention pass may delete for one target.

        A scan is deleted only when it is outside the age window *and* is
        not protected. Protection rules:

          * the newest ``keep_per_target`` scans are never deleted, so a
            high scan rate cannot prune the recent history down to nothing;
          * the newest *succeeded* scan is never deleted — it is the
            change-detection baseline, and losing it would make the next
            scan report every host as brand new.

        The age window and the count cap are independent limits: a scan must
        violate both to be a candidate.

        Pure selection logic — no deletes happen here — so it is directly
        unit-testable.
        """
        rows = list(
            self._s.execute(
                select(Scan.id, Scan.started_at, Scan.status).where(
                    Scan.target_id == target_id
                )
            ).all()
        )
        if not rows:
            return []

        # "Newest" means newest in time, not highest id. Those coincide in
        # normal operation (scans are appended as they run), but they diverge
        # for backfilled or replayed scans, where a lower id can carry a
        # more recent timestamp. Ordering on the timestamp keeps retention
        # correct either way; id breaks ties.
        newest_first = sorted(
            rows,
            key=lambda r: (r.started_at or datetime.min, r.id),
            reverse=True,
        )

        # 1. count cap: keep the newest N regardless of age
        protected: set[int] = {r.id for r in newest_first[:max(0, keep_per_target)]}

        # 2. the baseline: newest succeeded scan
        baseline = next((r for r in newest_first if r.status == "succeeded"), None)
        if baseline is not None:
            protected.add(baseline.id)

        # 3. age window
        cutoff = _utcnow() - timedelta(days=keep_days)
        deletable: list[int] = []
        for row in newest_first:
            if row.id in protected:
                continue
            started = row.started_at
            # `server_default=now()` is applied on INSERT and not re-read
            # afterwards, so a row created and flushed in this session can
            # still carry started_at=None. Treat that as "brand new" rather
            # than as an ancient scan, otherwise everything just written
            # would look deletable.
            if started is None or started < cutoff:
                deletable.append(row.id)

        return deletable


class ChangeRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def add_all(self, events: list[ChangeEvent]) -> None:
        self._s.add_all(events)
        self._s.flush()

    def for_scan(self, scan_id: int) -> list[ChangeEvent]:
        return list(
            self._s.scalars(
                select(ChangeEvent)
                .where(ChangeEvent.scan_id == scan_id)
                .order_by(ChangeEvent.change_type, ChangeEvent.host)
            )
        )

    def for_scans(self, scan_ids: list[int]) -> list[ChangeEvent]:
        if not scan_ids:
            return []
        return list(
            self._s.scalars(
                select(ChangeEvent)
                .where(ChangeEvent.scan_id.in_(scan_ids))
                .order_by(ChangeEvent.scan_id, ChangeEvent.change_type)
            )
        )

    def for_target_window(self, target_id: int, days: int) -> list[ChangeEvent]:
        cutoff = _utcnow() - timedelta(days=days)
        return list(
            self._s.scalars(
                select(ChangeEvent)
                .join(Scan, ChangeEvent.scan_id == Scan.id)
                .where(
                    Scan.target_id == target_id,
                    ChangeEvent.created_at.isnot(None),
                    ChangeEvent.created_at >= cutoff,
                )
                .order_by(desc(ChangeEvent.id))
            )
        )


class ScheduleRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def upsert(
        self, target_id: int, profile: str, interval_hours: int
    ) -> Schedule:
        """Create or reconfigure the (single) schedule for a target."""
        row = self._s.scalar(
            select(Schedule).where(Schedule.target_id == target_id)
        )
        if row is None:
            row = Schedule(
                target_id=target_id,
                profile=profile,
                interval_hours=interval_hours,
                enabled=True,
            )
            self._s.add(row)
        else:
            row.profile = profile
            row.interval_hours = interval_hours
            row.enabled = True
        self._s.flush()
        return row

    def enabled(self) -> list[Schedule]:
        return list(
            self._s.scalars(
                select(Schedule)
                .where(Schedule.enabled.is_(True))
                .options(joinedload(Schedule.target))
                .order_by(Schedule.id)
            ).unique()
        )

    def all(self) -> list[Schedule]:
        return list(
            self._s.scalars(
                select(Schedule)
                .options(joinedload(Schedule.target))
                .order_by(Schedule.id)
            ).unique()
        )

    def for_target(self, target_id: int) -> Schedule | None:
        return self._s.scalar(
            select(Schedule).where(Schedule.target_id == target_id)
        )

    def set_enabled(self, target_id: int, enabled: bool) -> Schedule | None:
        row = self.for_target(target_id)
        if row is None:
            return None
        row.enabled = enabled
        self._s.flush()
        return row

    def delete_for_target(self, target_id: int) -> bool:
        row = self.for_target(target_id)
        if row is None:
            return False
        self._s.delete(row)
        self._s.flush()
        return True

    def set_all_enabled(self, enabled: bool) -> int:
        rows = list(self._s.scalars(select(Schedule)))
        for row in rows:
            row.enabled = enabled
        self._s.flush()
        return len(rows)

    def mark_run(self, schedule_id: int, last_run: datetime, next_run: datetime) -> None:
        row = self._s.get(Schedule, schedule_id)
        if row is None:  # pragma: no cover - defensive
            return
        row.last_run_at = last_run
        row.next_run_at = next_run
        self._s.flush()

    def count_enabled(self) -> int:
        return int(
            self._s.scalar(
                select(func.count())
                .select_from(Schedule)
                .where(Schedule.enabled.is_(True))
            )
            or 0
        )


class OperatorChatRepository:
    """Remembers where scheduled alerts should be delivered."""

    def __init__(self, session: Session) -> None:
        self._s = session

    def remember(
        self, chat_id: int, user_id: int, username: str | None = None
    ) -> OperatorChat:
        row = self._s.scalar(
            select(OperatorChat).where(OperatorChat.chat_id == chat_id)
        )
        if row is None:
            row = OperatorChat(
                chat_id=chat_id, user_id=user_id, username=username
            )
            self._s.add(row)
        row.user_id = user_id
        row.username = username
        row.last_seen_at = _utcnow()
        self._s.flush()
        return row

    def primary(self) -> OperatorChat | None:
        """The earliest-registered operator chat — the alert destination."""
        return self._s.scalars(
            select(OperatorChat).order_by(OperatorChat.id).limit(1)
        ).first()

    def list(self) -> list[OperatorChat]:
        return list(self._s.scalars(select(OperatorChat).order_by(OperatorChat.id)))


# ---------------------------------------------------------------------------
# Policy rules (V3)
# ---------------------------------------------------------------------------


@dataclass
class RuleFilters:
    """Optional narrowing for :meth:`RuleRepository.list_rules`.

    Every field unset means "no filter". ``q`` is a case-insensitive
    substring match on the name.
    """

    rule_type: str | None = None
    enabled: bool | None = None
    scope: str | None = None
    q: str | None = None


@dataclass
class RuleCreate:
    """A new rule. ``value`` is normalized before storage."""

    name: str
    rule_type: str
    value: str
    priority: int = 50
    enabled: bool = True
    scope: str = "global"
    scope_id: str | None = None
    description: str | None = None


@dataclass
class RuleUpdate:
    """A partial update.

    Every field is ``None`` when absent, so an omitted key never overwrites a
    stored value with a default. ``name`` is intentionally *not* editable
    here: hits reference rules by id but display names, and a rename would
    make historical hits read differently than they did when written.
    """

    rule_type: str | None = None
    value: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    scope: str | None = None
    scope_id: str | None = None
    description: str | None = None


@dataclass
class RuleHitFilters:
    rule_id: int | None = None
    decision: str | None = None
    actor_id: int | None = None
    target: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    page: int = 1
    page_size: int = 50


class RuleRepository:
    """CRUD and queries for policy rules and their hit history.

    Value validation is delegated to :mod:`core.rule_values` so there is
    exactly one parser; this layer owns persistence and naming policy only.
    """

    def __init__(self, session: Session) -> None:
        self._s = session

    # -- reads --------------------------------------------------------
    def list_rules(self, filters: RuleFilters | None = None) -> list[Rule]:
        """All rules matching ``filters``, in evaluation order.

        Ordered by (priority, id) so the listing shows rules the way the
        engine will apply them, which is the only ordering that matters to
        whoever is editing them.
        """
        stmt = select(Rule)
        if filters is not None:
            if filters.rule_type:
                stmt = stmt.where(Rule.rule_type == filters.rule_type)
            if filters.enabled is not None:
                stmt = stmt.where(Rule.enabled.is_(filters.enabled))
            if filters.scope:
                stmt = stmt.where(Rule.scope == filters.scope)
            if filters.q:
                # Substring, case-insensitive. `contains` is portable across
                # SQLite and PostgreSQL; `ilike` is not.
                stmt = stmt.where(Rule.name.contains(filters.q))
        return list(
            self._s.scalars(stmt.order_by(Rule.priority, Rule.id))
        )

    def get_rule(self, rule_id: int) -> Rule | None:
        return self._s.get(Rule, rule_id)

    def get_by_name(self, name: str) -> Rule | None:
        return self._s.scalar(select(Rule).where(Rule.name == name))

    def load_engine_rules(self) -> list[Rule]:
        """Enabled rules, in evaluation order.

        The hot path: the bot calls this once per scan. It deliberately does
        no eager-loading or joining — the engine reads only scalar columns —
        and it does not filter by scope, because scope matching depends on
        the request and belongs to the engine.
        """
        return list(
            self._s.scalars(
                select(Rule)
                .where(Rule.enabled.is_(True))
                .order_by(Rule.priority, Rule.id)
            )
        )

    def count_enabled(self) -> int:
        return int(
            self._s.scalar(
                select(func.count())
                .select_from(Rule)
                .where(Rule.enabled.is_(True))
            )
            or 0
        )

    # -- writes -------------------------------------------------------
    def create_rule(self, data: RuleCreate, actor: str) -> Rule:
        """Create a rule, normalizing ``data.value`` first.

        Raises :class:`RepositoryError` for an unknown type or a malformed
        value (the caller maps that to 400) and for a duplicate name, which
        the database rejects and this translates to a 409.
        """
        normalized = _normalize(data.rule_type, data.value)

        row = Rule(
            name=data.name,
            rule_type=data.rule_type,
            value=normalized,
            priority=data.priority,
            enabled=data.enabled,
            scope=data.scope,
            scope_id=data.scope_id,
            description=data.description,
            created_by=actor,
        )
        # SAVEPOINT, not a bare flush: a duplicate name must undo only this
        # statement. A session-wide rollback would discard rules the caller
        # had already written in this transaction, which matters because
        # import writes many in one session.
        try:
            with self._s.begin_nested():
                self._s.add(row)
                self._s.flush()
        except IntegrityError as exc:
            raise RepositoryError(
                f"Rule '{data.name}' already exists."
            ) from exc
        return row

    def update_rule(
        self, rule_id: int, patch: RuleUpdate, actor: str
    ) -> Rule:
        """Apply a partial update and stamp ``updated_at``.

        ``actor`` is accepted for symmetry with create and for future
        per-field attribution; it is not persisted, because the schema has no
        updated_by column and inventing one here would need a migration.
        """
        row = self.get_rule(rule_id)
        if row is None:
            raise RepositoryError(f"No rule with id {rule_id}.")

        if patch.rule_type is not None:
            row.rule_type = patch.rule_type
        if patch.value is not None:
            # Re-validate against the row's *current* type: changing only the
            # value must be checked against the type already stored, and
            # changing only the type must be checked against the value
            # already stored. Both orders end up validated here.
            row.value = _normalize(row.rule_type, patch.value)
        if patch.priority is not None:
            row.priority = patch.priority
        if patch.enabled is not None:
            row.enabled = patch.enabled
        if patch.scope is not None:
            row.scope = patch.scope
        if patch.scope_id is not None:
            row.scope_id = patch.scope_id
        if patch.description is not None:
            row.description = patch.description

        row.updated_at = _utcnow()
        # SAVEPOINT for the same reason as create_rule: a rejected update
        # must not discard the caller's other work.
        try:
            with self._s.begin_nested():
                self._s.flush()
        except IntegrityError as exc:
            self._s.expire(row)
            raise RepositoryError(f"Could not update rule {rule_id}.") from exc
        return row

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule. Hit rows are kept — see :class:`RuleHit`.

        Returns False when there was nothing to delete, so callers can answer
        404 without a second query.
        """
        row = self.get_rule(rule_id)
        if row is None:
            return False
        self._s.delete(row)
        self._s.flush()
        return True

    def set_enabled(self, rule_id: int, enabled: bool) -> Rule:
        row = self.get_rule(rule_id)
        if row is None:
            raise RepositoryError(f"No rule with id {rule_id}.")
        row.enabled = enabled
        row.updated_at = _utcnow()
        self._s.flush()
        return row

    def reorder(self, ids: list[int]) -> int:
        """Set priorities to 1..N following ``ids``.

        Only the listed rules are touched, so an operator can pin one rule at
        the top without renumbering the other ninety. Ids that do not exist
        are skipped rather than raising: a stale drag-and-drop list should not
        fail the whole reorder. A repeated id is de-duplicated on its first
        occurrence, so the position the operator chose is the one kept.

        Returns how many rules were renumbered.
        """
        if not ids:
            return 0

        # Deduplicate on first occurrence. Without this a repeated id is
        # applied twice and the rule ends up at the *later* position, which is
        # not where the operator put it.
        ordered_ids: list[int] = []
        seen: set[int] = set()
        for rule_id in ids:
            if rule_id not in seen:
                seen.add(rule_id)
                ordered_ids.append(rule_id)

        rows = {
            row.id: row
            for row in self._s.scalars(
                select(Rule).where(Rule.id.in_(ordered_ids))
            )
        }
        touched = 0
        now = _utcnow()
        for index, rule_id in enumerate(ordered_ids, start=1):
            row = rows.get(rule_id)
            if row is None:
                continue
            row.priority = index
            row.updated_at = now
            touched += 1
        self._s.flush()
        return touched

    # -- hits ---------------------------------------------------------
    def record_rule_hit(
        self,
        rule_id: int,
        *,
        scan_id: int | None = None,
        target: str | None = None,
        decision: str,
        reason: str | None = None,
        actor_id: int | None = None,
        actor_username: str | None = None,
    ) -> RuleHit | None:
        """Record one rule evaluation and bump its counter.

        The hit row and the counter move in the same transaction, so the
        panel's hit_count can never disagree with the history it links to.
        Returns None when the rule has been deleted meanwhile, which is not
        an error: the evaluation already happened and there is nothing to
        attribute it to.
        """
        if decision not in ("allow", "deny"):
            raise RepositoryError(
                f"Unknown rule decision '{decision}' (expected allow or deny)."
            )

        row = self.get_rule(rule_id)
        if row is None:
            return None

        hit = RuleHit(
            rule_id=rule_id,
            scan_id=scan_id,
            target=target,
            decision=decision,
            reason=reason,
            actor_id=actor_id,
            actor_username=actor_username,
        )
        self._s.add(hit)
        row.hit_count = (row.hit_count or 0) + 1
        row.last_hit_at = _utcnow()
        self._s.flush()
        return hit

    def list_rule_hits(
        self, filters: RuleHitFilters | None = None
    ) -> tuple[list[RuleHit], int]:
        """One page of hit rows plus the total match count."""
        filters = filters or RuleHitFilters()
        stmt = select(RuleHit)
        count_stmt = select(func.count()).select_from(RuleHit)

        if filters.rule_id is not None:
            stmt = stmt.where(RuleHit.rule_id == filters.rule_id)
            count_stmt = count_stmt.where(RuleHit.rule_id == filters.rule_id)
        if filters.decision:
            stmt = stmt.where(RuleHit.decision == filters.decision)
            count_stmt = count_stmt.where(RuleHit.decision == filters.decision)
        if filters.actor_id is not None:
            stmt = stmt.where(RuleHit.actor_id == filters.actor_id)
            count_stmt = count_stmt.where(RuleHit.actor_id == filters.actor_id)
        if filters.target:
            stmt = stmt.where(RuleHit.target == filters.target)
            count_stmt = count_stmt.where(RuleHit.target == filters.target)
        if filters.since is not None:
            stmt = stmt.where(RuleHit.created_at >= filters.since)
            count_stmt = count_stmt.where(RuleHit.created_at >= filters.since)
        if filters.until is not None:
            stmt = stmt.where(RuleHit.created_at <= filters.until)
            count_stmt = count_stmt.where(RuleHit.created_at <= filters.until)

        total = int(self._s.scalar(count_stmt) or 0)
        page = max(1, filters.page)
        size = max(1, min(500, filters.page_size))
        rows = list(
            self._s.scalars(
                stmt.order_by(desc(RuleHit.created_at), desc(RuleHit.id))
                .offset((page - 1) * size)
                .limit(size)
            )
        )
        return rows, total

    def count_hits_since(self, cutoff: datetime) -> int:
        """Hits recorded since ``cutoff`` — backs the daily hit cap."""
        return int(
            self._s.scalar(
                select(func.count())
                .select_from(RuleHit)
                .where(RuleHit.created_at >= cutoff)
            )
            or 0
        )

    def purge_rule_hits(self, before: datetime) -> int:
        """Delete hits older than ``before``. Returns the row count.

        Rules themselves are never deleted by retention: a rule outliving its
        own history would make the surviving hit rows unexplainable.
        """
        result = self._s.execute(
            delete(RuleHit).where(RuleHit.created_at < before)
        )
        self._s.flush()
        return int(result.rowcount or 0)


def _normalize(rule_type: str, value: str) -> str:
    """Validate ``value`` for ``rule_type`` and return the canonical form.

    Raises :class:`RepositoryError` (not ValueError) so route handlers can
    catch one exception for every rejection reason and answer 400.
    """
    try:
        return validate_value(rule_type, value)
    except ValueError as exc:
        raise RepositoryError(str(exc)) from exc
