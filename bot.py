import asyncio
import contextlib
import json
import logging
import os
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Awaitable

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from flask import Flask, jsonify
from requests.adapters import HTTPAdapter
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
CHAT_ID_RAW = os.getenv("CHAT_ID", "").strip()

CHECK_INTERVAL = 300  # 5 minutes exactes
VERSION = "2.3.0"
PORT = int(os.getenv("PORT", "10000"))
STATE_FILE = Path("state.json")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN manquant dans le fichier .env")

CHAT_ID: int | None
if CHAT_ID_RAW:
    try:
        CHAT_ID = int(CHAT_ID_RAW)
    except ValueError as exc:
        raise RuntimeError("CHAT_ID doit être un nombre entier") from exc
else:
    CHAT_ID = None

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0 Safari/537.36"
    )
}

SERVERS = [
    ("France", "SSH UDP Custom", "https://sshocean.com/ssh-udp/france"),
    ("Germany", "SSH UDP Custom", "https://sshocean.com/ssh-udp/germany"),
    ("Netherlands", "SSH UDP Custom", "https://sshocean.com/ssh-udp/netherlands"),
    ("Poland", "SSH UDP Custom", "https://sshocean.com/ssh-udp/poland"),
    ("United Kingdom", "SSH UDP Custom", "https://sshocean.com/ssh-udp/united-kingdom"),
    ("United States", "SSH UDP Custom", "https://sshocean.com/ssh-udp/united-states"),
    ("Germany", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/germany"),
    ("Estonia", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/estonia"),
    ("Finland", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/finland"),
    ("France", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/france"),
    ("Latvia", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/latvia"),
    ("Netherlands", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/netherlands"),
    ("Sweden", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/sweden"),
    ("United Kingdom", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/united-kingdom"),
    ("United States", "SSH DNSTT", "https://sshocean.com/ssh-dnstt/united-states"),
]

FLAG_EMOJIS = {
    "France": "🇫🇷",
    "Germany": "🇩🇪",
    "Netherlands": "🇳🇱",
    "Poland": "🇵🇱",
    "United Kingdom": "🇬🇧",
    "United States": "🇺🇸",
    "Estonia": "🇪🇪",
    "Finland": "🇫🇮",
    "Latvia": "🇱🇻",
    "Sweden": "🇸🇪",
}

session = requests.Session()
session.headers.update(HEADERS)
adapter = HTTPAdapter(pool_connections=30, pool_maxsize=30)
session.mount("http://", adapter)
session.mount("https://", adapter)

scan_lock = asyncio.Lock()
flask_app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def human_duration(seconds: float) -> str:
    total = int(max(0, seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}j")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if sec or not parts:
        parts.append(f"{sec}s")
    return " ".join(parts)


def flag(country: str) -> str:
    return FLAG_EMOJIS.get(country, "🏳️")


def load_state() -> dict[str, Any]:
    default_state = {
        "servers": {},
        "alerts": [],
        "last_scan": None,
        "last_results": [],
        "started_at": now_dt().isoformat(),
        "scan_count": 0,
        "alert_count": 0,
    }

    if not STATE_FILE.exists():
        return default_state

    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default_state
        for key, value in default_state.items():
            data.setdefault(key, value)
        if not isinstance(data.get("servers"), dict):
            data["servers"] = {}
        if not isinstance(data.get("alerts"), list):
            data["alerts"] = []
        if not isinstance(data.get("last_results"), list):
            data["last_results"] = []
        return data
    except Exception:
        return default_state


def save_state(state: dict[str, Any]) -> None:
    tmp_file = STATE_FILE.with_suffix(".tmp")
    tmp_file.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp_file.replace(STATE_FILE)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def parse_server(country: str, protocol: str, url: str) -> dict[str, Any]:
    try:
        response = session.get(url, timeout=20)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "lxml")
        text = " ".join(soup.stripped_strings)
        lowered = normalize(text)

        if re.search(r"\boffline\b", lowered):
            status = "OFFLINE"
        elif re.search(r"\bonline\b", lowered):
            status = "ONLINE"
        else:
            status = "UNKNOWN"

        title_tag = soup.find(["h1", "h2", "h3"])
        title = title_tag.get_text(" ", strip=True) if title_tag else f"{protocol} • {country}"

        host_match = re.search(r"\b([a-z0-9.-]+\.ssht\.site)\b", text, re.I)
        hostname = host_match.group(1) if host_match else "Unknown"

        remaining_match = re.search(r"Remaining\s*[:\-]?\s*(\d+)", text, re.I)
        accounts = remaining_match.group(1) if remaining_match else "?"

        return {
            "country": country,
            "protocol": protocol,
            "title": title,
            "hostname": hostname,
            "accounts": accounts,
            "status": status,
            "url": url,
        }
    except Exception as exc:
        return {
            "country": country,
            "protocol": protocol,
            "title": f"{protocol} • {country}",
            "hostname": "Unknown",
            "accounts": "?",
            "status": "ERROR",
            "error": str(exc),
            "url": url,
        }


def status_icon(status: str) -> str:
    return {
        "ONLINE": "🟢",
        "OFFLINE": "🔴",
        "UNKNOWN": "⚪",
        "ERROR": "⚠️",
    }.get(status, "⚪")


def group_by_country(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for server in results:
        grouped[server["country"]].append(server)
    return dict(grouped)


def split_chunks(lines: list[str], limit: int = 3900) -> list[str]:
    chunks = []
    current = ""
    for line in lines:
        if len(current) + len(line) + 1 > limit:
            if current:
                chunks.append(current.rstrip())
            current = line + "\n"
        else:
            current += line + "\n"
    if current.strip():
        chunks.append(current.rstrip())
    return chunks


def command_list_text() -> str:
    return (
        "✨ <b>Commandes disponibles</b>\n\n"
        "👑 <b>Essentielles</b>\n"
        "/start — accueil luxueux\n"
        "/help — aide rapide\n"
        "/commands — toutes les commandes\n"
        "/status — état global\n"
        "/summary — résumé élégant\n"
        "/stats — statistiques détaillées\n"
        "/check — scan immédiat\n"
        "/refresh — actualiser le cache\n\n"
        "💎 <b>Serveurs</b>\n"
        "/servers — liste complète\n"
        "/online — serveurs en ligne\n"
        "/offline — serveurs hors ligne\n"
        "/udp — serveurs UDP\n"
        "/dnstt — serveurs DNSTT\n"
        "/country — groupé par pays\n"
        "/search <code>mot</code> — recherche rapide\n"
        "/host <code>nom</code> — recherche hostname\n"
        "/info <code>pays</code> — détails d’un pays\n\n"
        "🌟 <b>Système</b>\n"
        "/alerts — dernières alertes\n"
        "/ping — latence du bot\n"
        "/uptime — temps de fonctionnement\n"
        "/version — version du bot\n"
        "/about — informations"
    )


def build_overview(results: list[dict[str, Any]]) -> str:
    total = len(results)
    counts = Counter(server["status"] for server in results)
    state = load_state()

    last_scan = state.get("last_scan") or "Jamais"
    started_at = parse_iso(state.get("started_at"))
    uptime = human_duration((now_dt() - started_at).total_seconds()) if started_at else "Inconnu"

    return (
        "✨ <b>SSHOcean Monitor</b>\n"
        "💎 <i>Surveillance luxueuse et intelligente</i>\n\n"
        f"🕒 <b>Dernière vérification :</b> <code>{escape(str(last_scan))}</code>\n"
        f"⏳ <b>Uptime :</b> {escape(uptime)}\n"
        f"📦 <b>Total :</b> {total}\n"
        f"🟢 <b>En ligne :</b> {counts.get('ONLINE', 0)}\n"
        f"🔴 <b>Hors ligne :</b> {counts.get('OFFLINE', 0)}\n"
        f"⚪ <b>Inconnus :</b> {counts.get('UNKNOWN', 0)}\n"
        f"⚠️ <b>Erreurs :</b> {counts.get('ERROR', 0)}\n"
        f"🔁 <b>Scans :</b> {state.get('scan_count', 0)}\n"
        f"🚨 <b>Alertes :</b> {state.get('alert_count', 0)}\n\n"
        "Commandes premium :\n"
        "/commands — toutes les commandes\n"
        "/status — état global\n"
        "/check — scan immédiat\n"
        "/servers — liste complète\n"
        "/online — serveurs en ligne\n"
        "/offline — serveurs hors ligne\n"
        "/udp — serveurs UDP\n"
        "/dnstt — serveurs DNSTT\n"
        "/country — groupé par pays\n"
        "/search <code>mot</code> — recherche rapide\n"
        "/info <code>pays</code> — détails d’un pays\n"
        "/alerts — dernières alertes\n"
        "/ping — latence du bot\n"
        "/uptime — temps de fonctionnement\n"
        "/version — version du bot\n"
        "/about — informations"
    )


def build_server_card(server: dict[str, Any]) -> str:
    return (
        f"{flag(server['country'])} {status_icon(server['status'])} <b>{escape(server['country'])}</b> — {escape(server['protocol'])}\n"
        f"🖥️ {escape(server['title'])}\n"
        f"🌐 <code>{escape(server['hostname'])}</code>\n"
        f"📦 Remaining: <b>{escape(str(server['accounts']))}</b>\n"
        f"🔗 <a href=\"{escape(server['url'], quote=True)}\">Ouvrir la page</a>"
    )


def build_list_message(title: str, results: list[dict[str, Any]]) -> str:
    lines = [f"✨ <b>{escape(title)}</b>\n"]
    if not results:
        lines.append("Aucun résultat.")
        return "\n".join(lines)

    for server in results:
        lines.append(build_server_card(server))
        lines.append("")
    return "\n".join(lines).strip()


def build_grouped_countries(results: list[dict[str, Any]]) -> str:
    groups = group_by_country(results)
    lines = ["✨ <b>Serveurs groupés par pays</b>\n"]
    for country in sorted(groups.keys()):
        items = groups[country]
        counts = Counter(s["status"] for s in items)
        lines.append(
            f"{flag(country)} <b>{escape(country)}</b> — "
            f"Total {len(items)} | 🟢 {counts.get('ONLINE', 0)} | 🔴 {counts.get('OFFLINE', 0)} | ⚪ {counts.get('UNKNOWN', 0)} | ⚠️ {counts.get('ERROR', 0)}"
        )
        for server in items:
            lines.append(
                f"  • {flag(server['country'])} {status_icon(server['status'])} "
                f"{escape(server['protocol'])} — {escape(server['title'])}"
            )
        lines.append("")
    return "\n".join(lines).strip()


def build_alert_message(server: dict[str, Any]) -> str:
    return (
        "✨ <b>SSHOcean Alert</b>\n"
        "💎 <i>Un serveur vient de devenir disponible</i>\n\n"
        f"{flag(server['country'])} {status_icon(server['status'])} <b>{escape(server['status'])}</b>\n"
        f"📍 <b>{escape(server['country'])}</b> — {escape(server['protocol'])}\n"
        f"🖥️ {escape(server['title'])}\n"
        f"🌐 Host: <code>{escape(server['hostname'])}</code>\n"
        f"📦 Remaining: <b>{escape(str(server['accounts']))}</b>\n"
        f"🔗 <a href=\"{escape(server['url'], quote=True)}\">Voir la page</a>\n"
        f"🕒 {utc_now()}"
    )


def append_alert(state: dict[str, Any], server: dict[str, Any]) -> None:
    alerts = state.setdefault("alerts", [])
    alerts.insert(
        0,
        {
            "time": utc_now(),
            "country": server["country"],
            "protocol": server["protocol"],
            "title": server["title"],
            "hostname": server["hostname"],
            "status": server["status"],
            "url": server["url"],
        },
    )
    del alerts[20:]


async def send_alert(bot, server: dict[str, Any], state: dict[str, Any]) -> None:
    if CHAT_ID is None:
        logging.warning("CHAT_ID absent: alerte non envoyée")
        return
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=build_alert_message(server),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        append_alert(state, server)
        state["alert_count"] = int(state.get("alert_count", 0)) + 1
    except Exception:
        logging.exception("Impossible d'envoyer l'alerte Telegram")


async def scan_once(bot, notify_changes: bool = True) -> list[dict[str, Any]]:
    async with scan_lock:
        state = load_state()
        previous_status = state.get("servers", {})

        tasks = [
            asyncio.to_thread(parse_server, country, protocol, url)
            for country, protocol, url in SERVERS
        ]
        results = await asyncio.gather(*tasks)

        new_status = {}
        for server in results:
            key = server["url"]
            current = server["status"]
            prev = previous_status.get(key)

            if notify_changes and prev == "OFFLINE" and current == "ONLINE":
                await send_alert(bot, server, state)

            new_status[key] = current

        state["servers"] = new_status
        state["last_scan"] = utc_now()
        state["last_results"] = results
        state["scan_count"] = int(state.get("scan_count", 0)) + 1
        save_state(state)
        return results


async def monitor_loop(bot) -> None:
    while True:
        started = time.monotonic()
        try:
            await scan_once(bot, notify_changes=True)
        except Exception:
            logging.exception("Erreur dans la surveillance automatique")
        elapsed = time.monotonic() - started
        await asyncio.sleep(max(0, CHECK_INTERVAL - elapsed))


async def reply_long(update: Update, text: str) -> None:
    for chunk in split_chunks(text.splitlines()):
        await update.message.reply_text(
            chunk,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )


def get_last_results() -> list[dict[str, Any]]:
    return load_state().get("last_results", [])


def filter_results(results: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> list[dict[str, Any]]:
    return [server for server in results if predicate(server)]


def search_results(results: list[dict[str, Any]], term: str) -> list[dict[str, Any]]:
    t = normalize(term)
    return [
        server
        for server in results
        if t in normalize(server["country"])
        or t in normalize(server["protocol"])
        or t in normalize(server["title"])
        or t in normalize(server["hostname"])
        or t in normalize(server["url"])
    ]


async def safe_reply_html(update: Update, text: str) -> None:
    try:
        await update.message.reply_text(
            text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception:
        logging.exception("Erreur lors de l'envoi du message HTML")
        await update.message.reply_text(
            re.sub(r"<[^>]+>", "", text),
            disable_web_page_preview=True,
        )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await safe_reply_html(
        update,
        (
            "✨ <b>SSHOcean Monitor</b>\n"
            "💎 <i>Créé par 🇭 🇲 🇧</i>\n\n"
            "Le bot surveille automatiquement les serveurs toutes les <b>5 minutes exactes</b>.\n"
            "Tape /commands pour voir toutes les commandes disponibles."
        ),
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await safe_reply_html(update, command_list_text())


async def cmd_commands(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await safe_reply_html(update, command_list_text())


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun scan n’a encore été effectué. Utilise /check.")
        return
    await safe_reply_html(update, build_overview(results))


async def cmd_summary(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await cmd_status(update, context)


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    state = load_state()
    results = state.get("last_results", [])
    counts = Counter(server["status"] for server in results)

    started_at = parse_iso(state.get("started_at"))
    uptime = human_duration((now_dt() - started_at).total_seconds()) if started_at else "Inconnu"

    text = (
        "✨ <b>Statistiques détaillées</b>\n"
        "💎 <i>Tableau de bord premium</i>\n\n"
        f"⏳ <b>Uptime :</b> {escape(uptime)}\n"
        f"🔁 <b>Scans effectués :</b> {state.get('scan_count', 0)}\n"
        f"🚨 <b>Alertes envoyées :</b> {state.get('alert_count', 0)}\n"
        f"📦 <b>Total serveurs :</b> {len(results)}\n"
        f"🟢 <b>Online :</b> {counts.get('ONLINE', 0)}\n"
        f"🔴 <b>Offline :</b> {counts.get('OFFLINE', 0)}\n"
        f"⚪ <b>Unknown :</b> {counts.get('UNKNOWN', 0)}\n"
        f"⚠️ <b>Error :</b> {counts.get('ERROR', 0)}\n"
        f"🕒 <b>Dernière vérification :</b> <code>{escape(str(state.get('last_scan') or 'Jamais'))}</code>"
    )
    await safe_reply_html(update, text)


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("⏳ Scan immédiat en cours...")
    results = await scan_once(context.bot, notify_changes=False)
    await safe_reply_html(update, build_overview(results))


async def cmd_refresh(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("♻️ Actualisation du cache en cours...")
    results = await scan_once(context.bot, notify_changes=False)
    await safe_reply_html(update, build_overview(results))


async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    await reply_long(update, build_list_message("Liste complète des serveurs", results))


async def cmd_online(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    online = filter_results(results, lambda s: s["status"] == "ONLINE")
    await reply_long(update, build_list_message(f"Serveurs en ligne ({len(online)})", online))


async def cmd_offline(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    offline = filter_results(results, lambda s: s["status"] == "OFFLINE")
    await reply_long(update, build_list_message(f"Serveurs hors ligne ({len(offline)})", offline))


async def cmd_udp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    udp = filter_results(results, lambda s: "udp" in s["protocol"].lower())
    await reply_long(update, build_list_message(f"Serveurs UDP ({len(udp)})", udp))


async def cmd_dnstt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    dnstt = filter_results(results, lambda s: "dnstt" in s["protocol"].lower())
    await reply_long(update, build_list_message(f"Serveurs DNSTT ({len(dnstt)})", dnstt))


async def cmd_country(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return
    await reply_long(update, build_grouped_countries(results))


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return

    term = " ".join(context.args).strip()
    if not term:
        await update.message.reply_text("Utilisation : /search <mot-clé>")
        return

    matches = search_results(results, term)
    await reply_long(update, build_list_message(f"Résultats pour « {term} » ({len(matches)})", matches))


async def cmd_host(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return

    term = " ".join(context.args).strip()
    if not term:
        await update.message.reply_text("Utilisation : /host <nom>")
        return

    term_norm = normalize(term)
    matches = [s for s in results if term_norm in normalize(s["hostname"])]
    await reply_long(update, build_list_message(f"Recherche hostname « {term} » ({len(matches)})", matches))


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    results = get_last_results()
    if not results:
        await update.message.reply_text("Aucun résultat disponible. Lance /check.")
        return

    term = " ".join(context.args).strip()
    if not term:
        await update.message.reply_text("Utilisation : /info <pays>")
        return

    term_norm = normalize(term)
    matches = [
        s for s in results
        if term_norm in normalize(s["country"]) or term_norm in normalize(s["title"])
    ]

    if not matches:
        await update.message.reply_text(f"Aucun serveur trouvé pour : {term}")
        return

    await reply_long(update, build_list_message(f"Détails pour « {term} » ({len(matches)})", matches))


async def cmd_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    state = load_state()
    alerts = state.get("alerts", [])
    if not alerts:
        await update.message.reply_text("Aucune alerte enregistrée pour le moment.")
        return

    lines = ["✨ <b>Dernières alertes</b>\n"]
    for alert in alerts:
        lines.append(
            f"{flag(alert['country'])} {status_icon(alert['status'])} <b>{escape(alert['country'])}</b> — {escape(alert['protocol'])}\n"
            f"🖥️ {escape(alert['title'])}\n"
            f"🌐 <code>{escape(alert['hostname'])}</code>\n"
            f"🕒 {escape(alert['time'])}\n"
        )
    await reply_long(update, "\n".join(lines).strip())


async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    start = time.perf_counter()
    msg = await update.message.reply_text("🏓 Ping...")
    latency = (time.perf_counter() - start) * 1000
    await msg.edit_text(f"🏓 Pong — {latency:.0f} ms")


async def cmd_uptime(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    state = load_state()
    started_at = parse_iso(state.get("started_at"))
    if not started_at:
        await update.message.reply_text("Uptime indisponible.")
        return
    uptime = human_duration((now_dt() - started_at).total_seconds())
    await update.message.reply_text(f"⏳ Uptime du bot : {uptime}")


async def cmd_version(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(f"🔖 Version du bot : {VERSION}")


async def cmd_about(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "✨ <b>À propos</b>\n\n"
        "Bot Telegram de surveillance SSHOcean.\n"
        "Style luxueux, compact et intelligent.\n"
        "Créateur : <b>🇭 🇲 🇧</b>\n"
        "Surveillance automatique toutes les <b>5 minutes exactes</b>.\n"
        "Notifications envoyées lorsqu’un serveur passe de <b>OFFLINE</b> à <b>ONLINE</b>."
    )
    await safe_reply_html(update, text)


async def cmd_fallback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Commande inconnue. Tape /commands pour voir la liste.")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logging.exception("Erreur non gérée: %s", context.error)


@flask_app.get("/")
def home():
    return jsonify(
        status="online",
        service="SSHOcean Monitor",
        version=VERSION,
        time=utc_now(),
    )


@flask_app.get("/health")
def health():
    return jsonify(
        status="online",
        checked_at=utc_now(),
    )


def start_web_server() -> None:
    def run():
        flask_app.run(
            host="0.0.0.0",
            port=PORT,
            use_reloader=False,
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    start_web_server()

    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("commands", cmd_commands))
    application.add_handler(CommandHandler("cmds", cmd_commands))
    application.add_handler(CommandHandler("menu", cmd_commands))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("summary", cmd_summary))
    application.add_handler(CommandHandler("stats", cmd_stats))
    application.add_handler(CommandHandler("check", cmd_check))
    application.add_handler(CommandHandler("refresh", cmd_refresh))
    application.add_handler(CommandHandler("servers", cmd_servers))
    application.add_handler(CommandHandler("online", cmd_online))
    application.add_handler(CommandHandler("offline", cmd_offline))
    application.add_handler(CommandHandler("udp", cmd_udp))
    application.add_handler(CommandHandler("dnstt", cmd_dnstt))
    application.add_handler(CommandHandler("country", cmd_country))
    application.add_handler(CommandHandler("search", cmd_search))
    application.add_handler(CommandHandler("host", cmd_host))
    application.add_handler(CommandHandler("info", cmd_info))
    application.add_handler(CommandHandler("alerts", cmd_alerts))
    application.add_handler(CommandHandler("ping", cmd_ping))
    application.add_handler(CommandHandler("uptime", cmd_uptime))
    application.add_handler(CommandHandler("version", cmd_version))
    application.add_handler(CommandHandler("about", cmd_about))
    application.add_handler(CommandHandler("helpme", cmd_help))
    application.add_handler(CommandHandler("fallback", cmd_fallback))

    application.add_error_handler(error_handler)

    await application.initialize()
    await application.start()
    await application.updater.start_polling(drop_pending_updates=True)

    try:
        await scan_once(application.bot, notify_changes=False)
    except Exception:
        logging.exception("Erreur lors du scan initial")

    monitor_task = asyncio.create_task(monitor_loop(application.bot))
    logging.info("Bot lancé avec surveillance toutes les 5 minutes exactes.")

    try:
        await asyncio.Event().wait()
    finally:
        monitor_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await monitor_task
        await application.updater.stop()
        await application.stop()
        await application.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
