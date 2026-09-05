"""Überwacht alle Seiten einer oder mehrerer Sitemaps auf Änderungen im HTML-Quellcode."""

from __future__ import annotations

import difflib
import gzip
import hashlib
import json
import os
import re
import smtplib
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup

USER_AGENT = "htmltreelistener/1.0 (+github-actions)"
TIMEOUT = 30
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "8"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "state/hashes.json"))
SNAPSHOT_DIR = STATE_FILE.parent / "snapshots"
REPORT_WINDOW_HOURS = int(os.environ.get("REPORT_WINDOW_HOURS", "24"))
MAX_DIFF_LINES = int(os.environ.get("MAX_DIFF_LINES", "200"))
SLACK_MAX_CHARS = int(os.environ.get("SLACK_MAX_CHARS", "3500"))
ALWAYS_NOTIFY = os.environ.get("ALWAYS_NOTIFY", "true").lower() in ("1", "true", "yes")

# Regex-Muster für Werte, die sich bei jedem Abruf ändern und durch einen Platzhalter ersetzt werden.
# Standard: 13-stellige Hex-IDs in Anführungszeichen (WordPress uniqid(), z. B. Lightbox imageId / data-wp-key).
BUILTIN_PATTERNS = [r"(?<=[\"'])[0-9a-f]{13}(?=[\"'])"]
IGNORE_PATTERNS = [
    re.compile(p) for p in BUILTIN_PATTERNS + [l.strip() for l in os.environ.get("IGNORE_PATTERNS", "").splitlines() if l.strip()]
]

session = requests.Session()
session.headers["User-Agent"] = USER_AGENT

# Diffs enthalten beliebige Unicode-Zeichen; Windows-Konsolen sind sonst cp1252.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


@dataclass
class Site:
    sitemap: str
    slack_webhook: str | None = None
    mail_to: str | None = None
    # CSS-Selektoren für dynamische Bereiche, die vor dem Vergleich entfernt werden.
    ignore_selectors: list[str] = field(default_factory=list)


def split_selectors(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


def load_sites() -> list[Site]:
    """Liest SITEMAP_URL, SITEMAP_URL_2, SITEMAP_URL_3, ... samt zugehöriger Variablen."""
    # IGNORE_SELECTORS gilt für alle Sites; IGNORE_SELECTORS_n ergänzt sie für Site n.
    global_selectors = split_selectors(os.environ.get("IGNORE_SELECTORS", ""))
    sites: list[Site] = []
    n = 1
    while True:
        suffix = "" if n == 1 else f"_{n}"
        sitemap = os.environ.get(f"SITEMAP_URL{suffix}", "").strip()
        if not sitemap:
            break
        extra = split_selectors(os.environ.get(f"IGNORE_SELECTORS{suffix}", "")) if suffix else []
        sites.append(
            Site(
                sitemap=sitemap,
                slack_webhook=os.environ.get(f"SLACK_WEBHOOK_URL{suffix}") or None,
                mail_to=os.environ.get(f"MAIL_TO{suffix}") or os.environ.get("MAIL_TO") or None,
                ignore_selectors=global_selectors + [s for s in extra if s not in global_selectors],
            )
        )
        n += 1
    return sites


def fetch(url: str) -> bytes:
    resp = session.get(url, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.content
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def sitemap_urls(sitemap_url: str, seen: set[str] | None = None) -> list[str]:
    """Liest eine Sitemap oder einen Sitemap-Index rekursiv ein."""
    seen = seen if seen is not None else set()
    if sitemap_url in seen:
        return []
    seen.add(sitemap_url)

    root = ElementTree.fromstring(fetch(sitemap_url))
    tag = root.tag.split("}")[-1]
    locs = [el.text.strip() for el in root.iter() if el.tag.split("}")[-1] == "loc" and el.text]

    if tag == "sitemapindex":
        urls: list[str] = []
        for loc in locs:
            urls.extend(sitemap_urls(loc, seen))
        return urls
    return locs


def strip_ignored(html: str, selectors: list[str]) -> str:
    if not selectors:
        return html
    soup = BeautifulSoup(html, "html.parser")
    for selector in selectors:
        for el in soup.select(selector):
            el.decompose()
    return str(soup)


def normalize_html(html: str, selectors: list[str] | None = None) -> str:
    # Whitespace angleichen und jedes Tag auf eine eigene Zeile setzen, damit Diffs lesbar bleiben.
    html = strip_ignored(html.lstrip("\ufeff"), selectors or [])
    for pattern in IGNORE_PATTERNS:
        html = pattern.sub("«dyn»", html)
    html = re.sub(r"[ \t\r\f\v]+", " ", html)
    html = re.sub(r">\s*<", ">\n<", html)
    return "\n".join(line.strip() for line in html.splitlines() if line.strip())


def snapshot_path(url: str) -> Path:
    return SNAPSHOT_DIR / (hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ".html")


def make_diff(old: str, new: str) -> str:
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "vorher", "nachher", lineterm="", n=2))
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f"... ({len(lines) - MAX_DIFF_LINES} weitere Zeilen gekürzt)"]
    return "\n".join(lines)


def check_page(url: str, old_hash: str | None, selectors: list[str]) -> tuple[str, str | None, str | None, str | None]:
    """Liefert (url, hash, diff, fehler). Bei Änderung wird der Snapshot ersetzt."""
    try:
        html = normalize_html(fetch(url).decode("utf-8", errors="replace"), selectors)
        digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
        if digest == old_hash:
            return url, digest, None, None

        path = snapshot_path(url)
        diff = None
        if old_hash is not None and path.exists():
            diff = make_diff(path.read_text(encoding="utf-8"), html)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return url, digest, diff, None
    except Exception as exc:  # noqa: BLE001 – Fehler pro Seite sollen den Lauf nicht abbrechen
        return url, None, None, str(exc)


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def build_report(sitemap_url: str, changed: list[str], added: list[str], removed: list[str], errors: dict[str, str], recent: list[str]) -> str:
    lines = [f"Änderungen auf {sitemap_url}", ""]

    def section(title: str, items: list[str]) -> None:
        if items:
            lines.append(f"{title} ({len(items)}):")
            lines.extend(f"  - {item}" for item in sorted(items))
            lines.append("")

    section("Geänderte Seiten", changed)
    section("Neue Seiten", added)
    section("Entfernte Seiten", removed)
    section(f"Weitere Änderungen der letzten {REPORT_WINDOW_HOURS}h", recent)
    if errors:
        lines.append(f"Fehler beim Abruf ({len(errors)}):")
        lines.extend(f"  - {url}: {msg}" for url, msg in sorted(errors.items()))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_diff_text(diffs: dict[str, str], max_chars: int | None = None) -> str:
    if not diffs:
        return ""
    parts = ["", "Diffs:"]
    for url in sorted(diffs):
        parts.append(f"\n=== {url} ===\n{diffs[url] or '(kein Diff verfügbar – erster Snapshot)'}")
    text = "\n".join(parts)
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars].rstrip() + "\n... (Diff gekürzt, vollständig in der Mail)"
    return text + "\n"


def send_mail(subject: str, body: str, to: str | None) -> None:
    host = os.environ.get("SMTP_HOST")
    if not host or not to:
        print("Mail übersprungen: SMTP_HOST oder MAIL_TO fehlt")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", "monitor@localhost"))
    msg["To"] = to
    msg.set_content(body)

    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT)
    else:
        server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        server.starttls()
    with server:
        if user and password:
            server.login(user, password)
        server.send_message(msg)
    print(f"Mail an {to} gesendet")


def send_slack(text: str, webhook: str | None) -> None:
    if not webhook:
        print("Slack übersprungen: kein Webhook konfiguriert")
        return
    resp = session.post(webhook, json={"text": text}, timeout=TIMEOUT)
    resp.raise_for_status()
    print("Slack-Nachricht gesendet")


def notify(site: Site, subject: str, slack_text: str, mail_body: str) -> int:
    failures = []
    for sender in (lambda: send_slack(slack_text, site.slack_webhook), lambda: send_mail(subject, mail_body, site.mail_to)):
        try:
            sender()
        except Exception as exc:  # noqa: BLE001
            failures.append(str(exc))
            print(f"Benachrichtigung fehlgeschlagen: {exc}", file=sys.stderr)
    return 1 if failures else 0


def process_site(site: Site, state: dict, now: datetime) -> int:
    now_iso = now.isoformat(timespec="seconds")
    print(f"\n### {site.sitemap}")
    first_run = not any(entry.get("sitemap") == site.sitemap for entry in state.values())

    try:
        urls = sorted(set(sitemap_urls(site.sitemap)))
    except Exception as exc:  # noqa: BLE001
        print(f"Sitemap konnte nicht gelesen werden: {exc}", file=sys.stderr)
        text = f"Sitemap {site.sitemap} konnte nicht gelesen werden: {exc}\n"
        return notify(site, "[Website-Monitor] Fehler beim Lesen der Sitemap", text, text)
    print(f"{len(urls)} URLs aus Sitemap gelesen")

    results: dict[str, str] = {}
    diffs: dict[str, str] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(check_page, url, (state.get(url) or {}).get("hash"), site.ignore_selectors) for url in urls]
        for future in as_completed(futures):
            url, digest, diff, error = future.result()
            if digest:
                results[url] = digest
                if diff is not None:
                    diffs[url] = diff
            else:
                errors[url] = error or "unbekannter Fehler"

    changed, added = [], []
    for url, digest in results.items():
        entry = state.get(url)
        if entry is None:
            added.append(url)
            # Beim Erstlauf gibt es keine "Änderung", daher kein Zeitstempel.
            state[url] = {"sitemap": site.sitemap, "hash": digest, "last_changed": None if first_run else now_iso, "last_checked": now_iso}
        elif entry["hash"] != digest:
            changed.append(url)
            diffs.setdefault(url, "")
            state[url] = {"sitemap": site.sitemap, "hash": digest, "last_changed": now_iso, "last_checked": now_iso}
        else:
            entry["sitemap"] = site.sitemap
            entry["last_checked"] = now_iso

    # Seiten mit Abruf-Fehler behalten ihren alten Zustand, damit sie nicht als "entfernt" gelten.
    removed = [
        url for url, entry in state.items() if entry.get("sitemap") == site.sitemap and url not in results and url not in errors
    ]
    for url in removed:
        del state[url]
        snapshot_path(url).unlink(missing_ok=True)

    window_start = now - timedelta(hours=REPORT_WINDOW_HOURS)
    recent = [
        url
        for url, entry in state.items()
        if entry.get("sitemap") == site.sitemap
        and entry.get("last_changed")
        and datetime.fromisoformat(entry["last_changed"]) >= window_start
        and url not in changed
        and url not in added
    ]

    print(f"geändert: {len(changed)}, neu: {len(added)}, entfernt: {len(removed)}, fehler: {len(errors)}")

    if first_run:
        print("Erster Lauf – Basiszustand gespeichert")
        if not ALWAYS_NOTIFY:
            return 0
        text = f"Website-Monitor eingerichtet für {site.sitemap}: {len(urls)} Seiten als Basiszustand gespeichert.\n"
        return notify(site, "[Website-Monitor] Eingerichtet", text, text)

    if not (changed or added or removed):
        print("Keine Änderungen")
        if not ALWAYS_NOTIFY:
            return 0
        text = f"Keine Änderungen auf {site.sitemap} ({len(results)} Seiten geprüft).\n"
        if errors:
            text += f"\nFehler beim Abruf ({len(errors)}):\n" + "\n".join(f"  - {u}: {m}" for u, m in sorted(errors.items())) + "\n"
        return notify(site, "[Website-Monitor] Keine Änderungen", text, text)

    report = build_report(site.sitemap, changed, added, removed, errors, recent)
    mail_body = report + build_diff_text(diffs)
    slack_text = report + build_diff_text(diffs, SLACK_MAX_CHARS)
    print(mail_body)

    subject = f"[Website-Monitor] {len(changed)} geändert, {len(added)} neu, {len(removed)} entfernt"
    return notify(site, subject, slack_text, mail_body)


def main() -> int:
    sites = load_sites()
    if not sites:
        print("SITEMAP_URL ist nicht gesetzt", file=sys.stderr)
        return 2

    state = load_state()
    # Einträge aus älteren Versionen ohne "sitemap"-Feld gehören zur ersten Site.
    for entry in state.values():
        entry.setdefault("sitemap", sites[0].sitemap)

    now = datetime.now(timezone.utc)
    exit_code = 0
    for site in sites:
        exit_code = max(exit_code, process_site(site, state, now))
        save_state(state)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
