"""Random-access byte readers: local files and HTTP Range (so remote weights are never downloaded whole)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class ByteSourceError(RuntimeError):
    pass


class ByteSource(ABC):
    name: str
    size: int | None

    @abstractmethod
    def read(self, offset: int, length: int) -> bytes:
        """Return up to `length` bytes at `offset` (short only at end of source)."""

    def close(self) -> None:  # pragma: no cover - trivial
        pass


class LocalSource(ByteSource):
    def __init__(self, path: Path) -> None:
        self.name = str(path)
        self._fh = path.open("rb")
        self.size = path.stat().st_size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ByteSourceError("negative read")
        self._fh.seek(offset)
        return self._fh.read(length)

    def close(self) -> None:
        self._fh.close()


class HttpRangeSource(ByteSource):
    """
    Chunk-cached HTTP Range reader.

    GGUF metadata is a long run of small reads (one per vocabulary token), so reads
    are served from aligned chunks; `max_bytes` caps total transfer so a hostile
    header claiming a 10 GB string cannot make the scanner download the file.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        size: int | None = None,
        chunk_size: int = 4 * 1024 * 1024,
        max_bytes: int = 256_000_000,
        timeout: int = 30,
        session: requests.Session | None = None,
    ) -> None:
        self.name = url
        self._url = url
        self._headers = dict(headers or {})
        self._chunk = chunk_size
        self._max_bytes = max_bytes
        self._timeout = timeout
        self._session = session or requests.Session()
        self._cache: dict[int, bytes] = {}
        self.bytes_fetched = 0
        self.size = size if size is not None else self._probe_size()

    def _probe_size(self) -> int | None:
        try:
            r = self._session.get(
                self._url,
                headers={**self._headers, "Range": "bytes=0-0"},
                timeout=self._timeout,
                allow_redirects=True,
            )
            cr = r.headers.get("Content-Range", "")
            if "/" in cr and cr.rsplit("/", 1)[1].isdigit():
                return int(cr.rsplit("/", 1)[1])
        except requests.RequestException as e:
            logger.debug("size probe failed for %s: %s", self._url, e)
        return None

    def _fetch_chunk(self, index: int) -> bytes:
        if index in self._cache:
            return self._cache[index]
        start = index * self._chunk
        end = start + self._chunk - 1
        if self.size is not None:
            if start >= self.size:
                return b""
            end = min(end, self.size - 1)
        if self.bytes_fetched + (end - start + 1) > self._max_bytes:
            raise ByteSourceError(
                f"remote read budget exceeded ({self._max_bytes} bytes) — header is implausibly large"
            )
        try:
            r = self._session.get(
                self._url,
                headers={**self._headers, "Range": f"bytes={start}-{end}"},
                timeout=self._timeout,
                allow_redirects=True,
            )
        except requests.RequestException as e:
            raise ByteSourceError(f"range request failed: {e}") from e
        if r.status_code == 200:
            # Server ignored Range; refuse rather than stream an entire weight file.
            r.close()
            raise ByteSourceError("server does not support HTTP Range requests")
        if r.status_code not in (206,):
            raise ByteSourceError(f"range request returned HTTP {r.status_code}")
        data = r.content
        self.bytes_fetched += len(data)
        if len(self._cache) > 64:
            self._cache.pop(next(iter(self._cache)))
        self._cache[index] = data
        return data

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ByteSourceError("negative read")
        out = bytearray()
        pos = offset
        remaining = length
        while remaining > 0:
            idx, inner = divmod(pos, self._chunk)
            chunk = self._fetch_chunk(idx)
            piece = chunk[inner : inner + remaining]
            if not piece:
                break
            out += piece
            pos += len(piece)
            remaining -= len(piece)
            if len(chunk) < self._chunk:
                break
        return bytes(out)
