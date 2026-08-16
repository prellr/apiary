//! Telegram as a ChannelAdapter — Bot API long polling.
//!
//! The bot token is a platform shim, sealed to the agent like any
//! credential; the identity stays the npub and every interaction lands in
//! the signed log. Long polling (`getUpdates`) means no webhook, no
//! inbound port. `allowed_chats` is the human-owned gate: anyone can find
//! a bot, but the MANIFEST decides who may engage the agent ("*" opts out
//! deliberately). Telegram never delivers bot messages to other bots, so
//! Buzz's ping-pong guard is structurally unnecessary here.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const POLL_SECS: u64 = 15;

pub struct TelegramAdapter {
    client: reqwest::blocking::Client,
    token: String,
    bot_username: String,
    allowed_chats: Vec<String>,
    offset: i64,
}

impl TelegramAdapter {
    pub fn connect(token: &str, allowed_chats: Vec<String>) -> Result<Self, crate::Error> {
        if allowed_chats.is_empty() {
            return Err(crate::Error::Provider(
                "telegram presence requires allowed_chats (chat ids; [\"*\"] admits \
                 anyone — say so deliberately)"
                    .into(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(POLL_SECS + 10))
            .build()
            .map_err(|e| crate::Error::Provider(format!("telegram client: {e}")))?;
        let me: Value = client
            .get(format!("https://api.telegram.org/bot{token}/getMe"))
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("telegram getMe: {e}")))?;
        if me["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "telegram rejected the bot token: {}",
                me["description"].as_str().unwrap_or("unknown")
            )));
        }
        let bot_username = me["result"]["username"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            client,
            token: token.to_string(),
            bot_username,
            allowed_chats,
            offset: 0,
        })
    }

    fn call(&self, method: &str, body: Value) -> Result<Value, crate::Error> {
        self.client
            .post(format!(
                "https://api.telegram.org/bot{}/{method}",
                self.token
            ))
            .json(&body)
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("telegram {method}: {e}")))
    }

    fn chat_allowed(&self, chat_id: &str) -> bool {
        self.allowed_chats.iter().any(|c| c == "*" || c == chat_id)
    }

    /// Download a Telegram file by id, size-capped: an oversized or
    /// failed file is skipped, never fatal to the mention.
    fn fetch_file(&self, file_id: &str) -> Option<Vec<u8>> {
        const MAX_BYTES: u64 = crate::presence::MAX_ATTACHMENT_BYTES;
        let f = self.call("getFile", json!({"file_id": file_id})).ok()?;
        if f["result"]["file_size"].as_u64().unwrap_or(0) > MAX_BYTES {
            return None;
        }
        let path = f["result"]["file_path"].as_str()?;
        let bytes = self
            .client
            .get(format!(
                "https://api.telegram.org/file/bot{}/{path}",
                self.token
            ))
            .send()
            .ok()?
            .bytes()
            .ok()?;
        if bytes.len() as u64 > MAX_BYTES {
            return None;
        }
        Some(bytes.to_vec())
    }

    /// Everything attached to a message that the agent can take as DATA:
    /// the largest photo size, a voice note, or an audio file.
    fn attachments(&self, msg: &Value) -> Vec<crate::presence::Attachment> {
        use crate::presence::Attachment;
        use base64::Engine;
        let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
        let mut out = Vec::new();
        if let Some(id) = msg["photo"]
            .as_array()
            .and_then(|a| a.last())
            .and_then(|p| p["file_id"].as_str())
        {
            if let Some(bytes) = self.fetch_file(id) {
                out.push(Attachment::Image {
                    media_type: "image/jpeg".into(), // Telegram photos are JPEG
                    base64: b64(bytes),
                });
            }
        }
        // `voice` = recorded in-app (OGG/Opus); `audio` = an uploaded file.
        for key in ["voice", "audio"] {
            let a = &msg[key];
            let Some(id) = a["file_id"].as_str() else {
                continue;
            };
            if let Some(bytes) = self.fetch_file(id) {
                out.push(Attachment::Audio {
                    media_type: a["mime_type"].as_str().unwrap_or("audio/ogg").to_string(),
                    base64: b64(bytes),
                    duration_secs: a["duration"].as_f64().map(|d| d as f32),
                });
            }
        }
        out
    }

    /// Trigger rules: DMs always; groups on @botname or a reply to the bot.
    fn triggers(&self, msg: &Value) -> bool {
        let chat_type = msg["chat"]["type"].as_str().unwrap_or_default();
        if chat_type == "private" {
            return true;
        }
        let text = msg["text"]
            .as_str()
            .or_else(|| msg["caption"].as_str())
            .unwrap_or_default();
        if !self.bot_username.is_empty()
            && text
                .to_lowercase()
                .contains(&format!("@{}", self.bot_username.to_lowercase()))
        {
            return true;
        }
        msg["reply_to_message"]["from"]["username"].as_str() == Some(self.bot_username.as_str())
    }
}

impl crate::presence::ChannelAdapter for TelegramAdapter {
    fn kind(&self) -> &'static str {
        "telegram"
    }

    fn describe(&self) -> String {
        format!(
            "telegram: @{} long-polling ({} allowed chats)",
            self.bot_username,
            self.allowed_chats.len()
        )
    }

    fn next_mention(
        &mut self,
        stop: &AtomicBool,
    ) -> Result<Option<crate::presence::Mention>, crate::Error> {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let updates = match self.call(
            "getUpdates",
            json!({"timeout": POLL_SECS, "offset": self.offset, "allowed_updates": ["message"]}),
        ) {
            Ok(v) => v,
            Err(_) => {
                // Network hiccup: tick; the engine calls again.
                std::thread::sleep(Duration::from_secs(2));
                return Ok(None);
            }
        };
        for u in updates["result"].as_array().cloned().unwrap_or_default() {
            if let Some(id) = u["update_id"].as_i64() {
                self.offset = self.offset.max(id + 1);
            }
            let msg = &u["message"];
            // Text, a captioned photo/voice note, or a bare one all engage.
            let has_media =
                msg["photo"].is_array() || msg["voice"].is_object() || msg["audio"].is_object();
            let text = msg["text"]
                .as_str()
                .or_else(|| msg["caption"].as_str())
                .unwrap_or_default()
                .to_string();
            if text.is_empty() && !has_media {
                continue;
            }
            let chat_id = match msg["chat"]["id"].as_i64() {
                Some(id) => id.to_string(),
                None => continue,
            };
            if !self.chat_allowed(&chat_id) || !self.triggers(msg) {
                continue;
            }
            let author = msg["from"]["username"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| msg["from"]["id"].as_i64().unwrap_or(0).to_string());
            let reply_ref = msg["message_id"].as_i64().unwrap_or(0).to_string();
            let attachments = if has_media {
                self.attachments(msg)
            } else {
                Vec::new()
            };
            let text = if text.is_empty() {
                if msg["voice"].is_object() || msg["audio"].is_object() {
                    "(a voice message, with no caption)".to_string()
                } else {
                    "(an image, with no caption)".to_string()
                }
            } else {
                text
            };
            return Ok(Some(crate::presence::Mention {
                channel: chat_id,
                author,
                text,
                reply_ref,
                attachments,
            }));
        }
        Ok(None) // quiet poll = tick
    }

    fn reply(
        &mut self,
        mention: &crate::presence::Mention,
        text: &str,
    ) -> Result<String, crate::Error> {
        let resp = self.call(
            "sendMessage",
            json!({
                "chat_id": mention.channel.parse::<i64>().unwrap_or_default(),
                "text": text,
                "reply_to_message_id": mention.reply_ref.parse::<i64>().unwrap_or_default(),
            }),
        )?;
        if resp["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "telegram sendMessage refused: {}",
                resp["description"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(resp["result"]["message_id"]
            .as_i64()
            .unwrap_or_default()
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> TelegramAdapter {
        TelegramAdapter {
            client: reqwest::blocking::Client::new(),
            token: "t".into(),
            bot_username: "scout_bot".into(),
            allowed_chats: vec!["100".into()],
            offset: 0,
        }
    }

    #[test]
    fn dms_trigger_groups_need_mention() {
        let a = adapter();
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "text": "hello"})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "text": "hello"})));
        assert!(a.triggers(&json!({"chat": {"type": "group"}, "text": "hey @Scout_Bot help"})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "text": "yes",
            "reply_to_message": {"from": {"username": "scout_bot"}}
        })));
    }

    #[test]
    fn captioned_photos_trigger_like_text() {
        let a = adapter();
        // A bare photo in a DM engages; in a group it needs a caption mention.
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "photo": [{}]})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "photo": [{}]})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "photo": [{}],
            "caption": "what is this @scout_bot?"
        })));
    }

    #[test]
    fn voice_notes_engage_like_photos() {
        let a = adapter();
        // Bare voice note in a DM engages; in a group it needs a caption mention.
        assert!(a.triggers(&json!({"chat": {"type": "private"}, "voice": {"file_id": "v"}})));
        assert!(!a.triggers(&json!({"chat": {"type": "group"}, "voice": {"file_id": "v"}})));
        assert!(a.triggers(&json!({
            "chat": {"type": "group"}, "voice": {"file_id": "v"},
            "caption": "@scout_bot listen to this"
        })));
    }

    #[test]
    fn allowlist_is_default_deny() {
        let a = adapter();
        assert!(a.chat_allowed("100"));
        assert!(!a.chat_allowed("999"));
        let mut open = adapter();
        open.allowed_chats = vec!["*".into()];
        assert!(open.chat_allowed("999"));
    }
}
