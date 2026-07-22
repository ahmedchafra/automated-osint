"""Telegram channel monitor collector.

Uses Telethon to search public Telegram channels and groups for mentions
of the target domain, brand name, or leaked credentials.

Setup:
  1. Get API credentials from https://my.telegram.org (API_ID, API_HASH)
  2. Run once to create session string:
     python -c "
     from telethon.sync import TelegramClient
     from telethon.sessions import StringSession
     client = TelegramClient(StringSession(), API_ID, API_HASH)
     client.start()
     print(client.session.save())
     "
  3. Set TG_SESSION_STRING in .env

Docs: https://docs.telethon.dev/
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List

from collectors.base import BaseCollector, CollectorMetadata
from app.config import settings


class TelegramMonitorCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="telegram_monitor",
        vector="SEARCH",
        description="Telegram channel/group mention monitor (Telethon)",
        passive=True,
        requires_api_key=True,
        api_key_env="TG_API_ID",
    )

    # Maximum messages to scan per channel
    MAX_MESSAGES = 500
    # Maximum channels to check
    MAX_CHANNELS = 20

    def __init__(self):
        super().__init__()
        self._client = None

    def _get_client(self):
        """Lazy-initialize Telethon client."""
        if self._client is not None:
            return self._client
        try:
            from telethon import TelegramClient
            from telethon.sessions import StringSession

            api_id = settings.TG_API_ID or ""
            api_hash = settings.TG_API_HASH or ""
            session_string = settings.TG_SESSION_STRING or ""

            if not api_id or not api_hash:
                print("[telegram_monitor] TG_API_ID and TG_API_HASH required")
                return None

            if session_string:
                self._client = TelegramClient(
                    StringSession(session_string), int(api_id), api_hash
                )
            else:
                # No session string — can't authenticate
                print("[telegram_monitor] TG_SESSION_STRING required. Generate one first.")
                return None
        except ImportError:
            print("[telegram_monitor] Telethon not installed. Run: pip install telethon")
            self._client = None
        return self._client

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Search Telegram for mentions of the target domain."""
        client = self._get_client()
        if client is None:
            return []

        # Extract brand name from domain
        brand = target.split(".")[0].lower()
        domain_pattern = re.escape(target.lower())

        results: List[Dict[str, Any]] = []

        try:
            await client.connect()
            if not await client.is_user_authorized():
                print("[telegram_monitor] Not authorized. Generate a session string first.")
                return []

            # 1. Search for channels/groups matching the brand
            channels = await self._search_channels(client, brand)

            # 2. Scan each channel for mentions
            for channel in channels[:self.MAX_CHANNELS]:
                mentions = await self._scan_channel(
                    client, channel, target, brand, domain_pattern
                )
                results.extend(mentions)

        except Exception as e:
            print(f"[telegram_monitor] error: {e}")
            return []
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

        return results

    async def _search_channels(self, client, brand: str) -> list:
        """Search for public channels/groups matching the brand name."""
        channels = []
        try:
            from telethon.tl.functions.contacts import SearchRequest
            result = await client(SearchRequest(q=brand, limit=20))
            for chat in result.chats:
                channels.append(chat)
        except Exception as e:
            print(f"[telegram_monitor] channel search error: {e}")
        return channels

    async def _scan_channel(self, client, channel, target: str, brand: str, domain_pattern: str) -> List[Dict[str, Any]]:
        """Scan a channel's recent messages for mentions of the target."""
        results = []
        mention_count = 0

        try:
            async for message in client.iter_messages(
                channel, limit=self.MAX_MESSAGES
            ):
                if not message.text:
                    continue

                text_lower = message.text.lower()

                # Check for domain or brand mention
                if target.lower() in text_lower or brand in text_lower:
                    mention_count += 1

                    # Classify the mention
                    mention_type = self._classify_mention(text_lower)

                    # Only include if it's potentially sensitive
                    if mention_type != "generic":
                        results.append({
                            "type": "telegram_mention",
                            "channel_name": getattr(channel, 'title', str(channel.id)),
                            "channel_id": channel.id,
                            "message_id": message.id,
                            "message_text": message.text[:500],  # truncate
                            "date": message.date.isoformat() if message.date else "",
                            "mention_type": mention_type,
                            "target_domain": target,
                            "target_brand": brand,
                        })

        except Exception as e:
            print(f"[telegram_monitor] scan error for channel {channel.id}: {e}")

        # Always add a summary finding for the channel
        if mention_count > 0:
            results.insert(0, {
                "type": "telegram_channel",
                "channel_name": getattr(channel, 'title', str(channel.id)),
                "channel_id": channel.id,
                "mention_count": mention_count,
                "target_domain": target,
                "target_brand": brand,
            })

        return results

    def _classify_mention(self, text: str) -> str:
        """Classify the type of mention in a message."""
        credential_keywords = [
            "password", "passwd", "pwd", "credential", "login", "username",
            "api_key", "apikey", "secret", "token", "private key", "leak",
            "breach", "dump", "database", "db", "access", "vpn", "ssh",
        ]
        vulnerability_keywords = [
            "vulnerability", "exploit", "cve", "rce", "xss", "sqli",
            "injection", "0day", "zero-day", "patch", "security",
        ]
        phishing_keywords = [
            "phishing", "fake", "spoof", "impersonate", "scam",
        ]

        for kw in credential_keywords:
            if kw in text:
                return "credential_mention"
        for kw in vulnerability_keywords:
            if kw in text:
                return "vulnerability_mention"
        for kw in phishing_keywords:
            if kw in text:
                return "phishing_mention"

        return "generic"

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Telegram data into standard Finding format."""
        raw_type = raw.get("type", "")

        if raw_type == "telegram_channel":
            return {
                "entity_type": "TELEGRAM_CHANNEL",
                "entity_value": f"tg://channel/{raw['channel_id']}",
                "severity": "INFO",
                "confidence": 0.6,
                "normalized_data": {
                    "channel_name": raw["channel_name"],
                    "channel_id": raw["channel_id"],
                    "mention_count": raw.get("mention_count", 0),
                    "target_domain": raw.get("target_domain", ""),
                    "target_brand": raw.get("target_brand", ""),
                    "source": "telegram_monitor",
                },
            }

        # telegram_mention
        mention_type = raw.get("mention_type", "generic")
        severity_map = {
            "credential_mention": "HIGH",
            "vulnerability_mention": "MEDIUM",
            "phishing_mention": "HIGH",
            "generic": "LOW",
        }

        return {
            "entity_type": "TELEGRAM_MESSAGE",
            "entity_value": f"tg://message/{raw['channel_id']}/{raw['message_id']}",
            "severity": severity_map.get(mention_type, "LOW"),
            "confidence": 0.7,
            "normalized_data": {
                "channel_name": raw.get("channel_name", ""),
                "channel_id": raw.get("channel_id", ""),
                "message_id": raw.get("message_id", ""),
                "message_text": raw.get("message_text", ""),
                "date": raw.get("date", ""),
                "mention_type": mention_type,
                "target_domain": raw.get("target_domain", ""),
                "target_brand": raw.get("target_brand", ""),
                "source": "telegram_monitor",
            },
        }
