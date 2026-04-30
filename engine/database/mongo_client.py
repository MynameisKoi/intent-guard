"""MongoDB persistence for scan reports and embedded topology fallback."""

import logging
from datetime import datetime, timezone
from typing import Any

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from config import settings

logger = logging.getLogger(__name__)


class MongoStore:
    def __init__(self) -> None:
        self._client: MongoClient | None = None
        self._db = None
        try:
            self._client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000)
            self._client.admin.command("ping")
            self._db = self._client[settings.mongo_db]
            logger.info("Connected to MongoDB %s/%s", settings.mongo_uri, settings.mongo_db)
        except PyMongoError as e:
            logger.warning("MongoDB unavailable (%s). Reports will only work in-memory for this process.", e)
            self._client = None
            self._db = None

    @property
    def available(self) -> bool:
        return self._db is not None

    def save_scan(self, doc: dict[str, Any]) -> None:
        if self._db is None:
            return
        self._db.scans.update_one(
            {"scan_id": doc["scan_id"]},
            {"$set": doc},
            upsert=True,
        )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        if self._db is None:
            return None
        return self._db.scans.find_one({"scan_id": scan_id})

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        if self._db is None:
            return []
        cur = (
            self._db.scans.find({}, projection={"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        return list(cur)

    def list_scan_ids_by_target(self, target: str) -> list[str]:
        if self._db is None:
            return []
        cur = self._db.scans.find({"target": target}, projection={"scan_id": 1})
        out: list[str] = []
        for row in cur:
            sid = row.get("scan_id")
            if isinstance(sid, str) and sid:
                out.append(sid)
        return out

    def delete_scans_by_target(self, target: str) -> int:
        if self._db is None:
            return 0
        res = self._db.scans.delete_many({"target": target})
        return int(res.deleted_count or 0)

    @staticmethod
    def now_iso() -> datetime:
        return datetime.now(timezone.utc)


# Process-level singleton for API
_store: MongoStore | None = None


def get_mongo_store() -> MongoStore:
    global _store
    if _store is None:
        _store = MongoStore()
    return _store
