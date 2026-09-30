"""SQLite persistence for incidents and the action audit log."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .models import ActionType, Incident


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL" if self.path != ":memory:" else "PRAGMA journal_mode=MEMORY")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                external_id TEXT,
                created TEXT NOT NULL,
                updated TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_incidents_external ON incidents(external_id);
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                action_id TEXT,
                action_type TEXT,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_audit_type_ts ON audit(action_type, ts);
            """
        )
        self._conn.commit()

    # ----------------------------------------------------------- incidents
    def save(self, incident: Incident) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = incident.model_dump_json()
        with self._lock:
            self._conn.execute(
                "INSERT INTO incidents(id, external_id, created, updated, data) VALUES (?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id, updated=excluded.updated, "
                "data=excluded.data",
                (incident.id, incident.external_id, incident.created.isoformat(), now, payload),
            )
            self._conn.commit()

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            row = self._conn.execute("SELECT data FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def find_by_external(self, external_id: str) -> Optional[Incident]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM incidents WHERE external_id=? ORDER BY created DESC LIMIT 1",
                (external_id,)).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def list(self, limit: int = 100) -> list[Incident]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM incidents ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [Incident.model_validate_json(r[0]) for r in rows]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM incidents")
            self._conn.execute("DELETE FROM audit")
            self._conn.commit()

    # ----------------------------------------------------------- audit
    def audit(self, incident_id: str, event: str, actor: str, *, action_id: str | None = None,
              action_type: ActionType | None = None, detail: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit(ts, incident_id, action_id, action_type, event, actor, detail) "
                "VALUES (?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), incident_id, action_id,
                 action_type.value if action_type else None, event, actor,
                 json.dumps(detail or {}, default=str)),
            )
            self._conn.commit()

    def executed_in_last_hour(self, action_type: ActionType) -> int:
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM audit WHERE action_type=? AND event='executed' AND actor='agent' "
                "AND ts>=?", (action_type.value, since)).fetchone()
        return int(row[0])

    def audit_log(self, incident_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        q = "SELECT ts, incident_id, action_id, action_type, event, actor, detail FROM audit"
        args: tuple = ()
        if incident_id:
            q += " WHERE incident_id=?"
            args = (incident_id,)
        q += " ORDER BY seq DESC LIMIT ?"
        args += (limit,)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        keys = ["ts", "incident_id", "action_id", "action_type", "event", "actor", "detail"]
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["detail"] = json.loads(d["detail"] or "{}")
            out.append(d)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
