"""Bounded CYFIRMA public-research collection, isolated from STIX IOC feeds."""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any


DEFAULT_URL = "https://www.cyfirma.com/research/"
MAX_RESPONSE_BYTES = 1_500_000


class _ListingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.current: dict[str, Any] | None = None
        self.items: list[dict[str, Any]] = []
        self._tag = ""
        self._root_tag = ""
        self._tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tags.append(tag)
        attr = dict(attrs)
        is_listing_row = tag == "article" or (tag == "div" and "blog-row" in (attr.get("class") or "").split())
        if self.current is None and is_listing_row:
            self.depth = 1
            self._root_tag = tag
            self.current = {"title_parts": [], "excerpt_parts": [], "url": "", "published_at": ""}
        elif self.current is not None and self.depth and tag in {"article", "div"}:
            self.depth += 1
        if self.current is not None and self.depth:
            if tag == "a" and attr.get("href") and not self.current["url"]:
                self.current["url"] = attr["href"]
            if tag == "time":
                self.current["published_at"] = attr.get("datetime") or ""
            self._tag = tag

    def handle_endtag(self, tag: str) -> None:
        if self.current is not None and self.depth and tag in {"article", "div"}:
            self.depth -= 1
            if self.depth == 0 and self.current:
                title = " ".join(self.current["title_parts"]).strip()
                excerpt = " ".join(self.current["excerpt_parts"]).strip()
                if title and self.current["url"]:
                    self.items.append({"title": title[:300], "url": self.current["url"],
                                       "published_at": self.current["published_at"][:64], "excerpt": excerpt[:1400]})
                self.current = None
                self._root_tag = ""
        if tag == self._tag:
            self._tag = ""
        if self._tags:
            self._tags.pop()

    def handle_data(self, data: str) -> None:
        if not self.current or not self.depth:
            return
        text = " ".join(data.split())
        if not text:
            return
        if any(tag in {"h1", "h2", "h3", "h4", "h5", "h6"} for tag in self._tags):
            self.current["title_parts"].append(text)
        elif any(tag in {"p", "time", "date"} for tag in self._tags):
            self.current["excerpt_parts"].append(text)
            if any(tag in {"time", "date"} for tag in self._tags) and not self.current["published_at"]:
                self.current["published_at"] = text


def _safe_url(value: str, base: str = DEFAULT_URL) -> str:
    resolved = urllib.parse.urljoin(base, value)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.scheme != "https" or parsed.netloc not in {"www.cyfirma.com", "cyfirma.com"}:
        return ""
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def fetch_listing(url: str = DEFAULT_URL, limit: int = 25, timeout: int = 12) -> list[dict[str, Any]]:
    """Fetch a public listing page only; no article pages, PDFs, STIX, or TAXII calls."""
    listing_url = _safe_url(url)
    if not listing_url:
        raise ValueError("CYFIRMA research URL must be https://www.cyfirma.com/")
    request = urllib.request.Request(listing_url, headers={"User-Agent": "Wazuh-MCP-SOC/1.0 research-ledger"})
    with urllib.request.urlopen(request, timeout=max(3, min(int(timeout), 30))) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("CYFIRMA research listing exceeded response limit")
    parser = _ListingParser()
    parser.feed(raw.decode("utf-8", errors="replace"))
    output, seen = [], set()
    for item in parser.items:
        item["url"] = _safe_url(str(item.get("url") or ""), listing_url)
        title = re.sub(r"\s+", " ", str(item.get("title") or "")).strip()
        if not item["url"] or not title:
            continue
        key = item["url"]
        if key in seen:
            continue
        seen.add(key)
        output.append({"title": title, "url": item["url"], "published_at": item.get("published_at") or "",
                       "excerpt": re.sub(r"\s+", " ", str(item.get("excerpt") or "")).strip()[:1400]})
        if len(output) >= max(1, min(int(limit), 100)):
            break
    return output


def ensure_schema(db) -> None:
    db.execute('''CREATE TABLE IF NOT EXISTS cyfirma_research (
        item_key TEXT PRIMARY KEY, collected_at REAL NOT NULL, published_at TEXT, published_epoch REAL,
        title TEXT NOT NULL, url TEXT NOT NULL, excerpt TEXT, data TEXT NOT NULL)''')
    columns = {row[1] for row in db.execute("PRAGMA table_info(cyfirma_research)").fetchall()}
    if "published_epoch" not in columns:
        db.execute("ALTER TABLE cyfirma_research ADD COLUMN published_epoch REAL")
    # Legacy rows did not retain a parseable publication timestamp. Keep them visible
    # in date views by using their original collection time as an explicit fallback.
    db.execute("UPDATE cyfirma_research SET published_epoch=collected_at WHERE published_epoch IS NULL")
    db.execute("CREATE INDEX IF NOT EXISTS cyfirma_research_collected ON cyfirma_research(collected_at DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS cyfirma_research_published ON cyfirma_research(published_epoch DESC)")


def _publication_epoch(value: str, fallback: float) -> float:
    value = value.strip()
    if not value:
        return fallback
    normalized = value.replace("Z", "+00:00")
    for candidate in (normalized, normalized[:10]):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            pass
    for pattern in ("%B %d, %Y", "%d %B %Y", "%d %b %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(value, pattern).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    return fallback


def store(db, items: list[dict[str, Any]], collected_at: float | None = None) -> int:
    ensure_schema(db)
    collected_at = float(collected_at or time.time())
    rows = []
    for item in items:
        title = str(item.get("title") or "").strip()[:300]
        url = _safe_url(str(item.get("url") or ""))
        if not title or not url:
            continue
        published = str(item.get("published_at") or "")[:64]
        published_epoch = _publication_epoch(published, collected_at)
        key = hashlib.sha256(f"{url}\x1f{title}".encode("utf-8")).hexdigest()
        data = {"title": title, "url": url, "published_at": published,
                "excerpt": str(item.get("excerpt") or "")[:1400], "source": "CYFIRMA public research archive"}
        rows.append((key, collected_at, published, published_epoch, title, url, data["excerpt"], json.dumps(data, separators=(",", ":"))))
    db.executemany("""INSERT INTO cyfirma_research(item_key,collected_at,published_at,published_epoch,title,url,excerpt,data)
        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(item_key) DO UPDATE SET
        collected_at=excluded.collected_at,published_at=excluded.published_at,published_epoch=excluded.published_epoch,
        title=excluded.title,url=excluded.url,excerpt=excluded.excerpt,data=excluded.data""", rows)
    return len(rows)


def history(db, start: str | None = None, end: str | None = None, limit: int = 30) -> dict[str, Any]:
    ensure_schema(db)
    limit = max(1, min(int(limit), 100))
    filters, params = [], []
    if start:
        filters.append("published_epoch>=?")
        params.append(datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp())
    if end:
        filters.append("published_epoch<?")
        params.append(datetime.fromisoformat(end.replace("Z", "+00:00")).timestamp())
    where = " WHERE " + " AND ".join(filters) if filters else ""
    total = int(db.execute("SELECT COUNT(*) FROM cyfirma_research" + where, params).fetchone()[0] or 0)
    rows = db.execute("SELECT data,collected_at,published_epoch FROM cyfirma_research" + where + " ORDER BY published_epoch DESC,title LIMIT ?", (*params, limit)).fetchall()
    items = []
    for raw, collected_at, published_epoch in rows:
        try:
            item = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        item["collected_at"] = datetime.fromtimestamp(collected_at, timezone.utc).isoformat()
        item["published_at"] = item.get("published_at") or datetime.fromtimestamp(published_epoch, timezone.utc).date().isoformat()
        items.append(item)
    return {"source": "CYFIRMA public research archive", "total": total, "items": items,
            "provider_calls": 0, "storage": "soc-automation SQLite research ledger"}
