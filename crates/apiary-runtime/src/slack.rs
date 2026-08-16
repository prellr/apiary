//! Slack as a ChannelAdapter — Socket Mode.
//!
//! Socket Mode is a WebSocket the CLIENT opens (`apps.connections.open`),
//! so there is no inbound port — the same posture as Telegram's long poll.
//! Two Slack credentials travel as ONE sealed JSON blob:
//! `{"app_token":"xapp-…","bot_token":"xoxb-…"}` — the app token opens the
//! socket, the bot token replies via `chat.postMessage`. Triggers:
//! `app_mention` events and DMs; `allowed_channels` optionally narrows
//! further (Slack app installation already gates the workspace). Events
//! are acked by envelope id; Slack retries unacked events, and the
//! mention log entry makes redelivery visible.

use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

pub struct SlackAdapter {
    http: reqwest::blocking::Client,
    app_token: String,
    bot_token: String,
    rules: SlackRules,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

/// The socket-free half: trigger rules, allowlist, and redelivery
/// suppression — testable without a live connection.
pub struct SlackRules {
    bot_user_id: String,
    allowed_channels: Vec<String>,
    /// Recently seen event ids — Slack redelivers unacked events; a small
    /// ring keeps redelivery from double-running the governed path.
    seen: std::collections::VecDeque<String>,
}

fn open_socket(
    http: &reqwest::blocking::Client,
    app_token: &str,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, crate::Error> {
    let opened: Value = http
        .post("https://slack.com/api/apps.connections.open")
        .bearer_auth(app_token)
        .send()
        .and_then(|r| r.json())
        .map_err(|e| crate::Error::Provider(format!("slack connections.open: {e}")))?;
    if opened["ok"].as_bool() != Some(true) {
        return Err(crate::Error::Provider(format!(
            "slack refused the app token: {}",
            opened["error"].as_str().unwrap_or("unknown")
        )));
    }
    let url = opened["url"]
        .as_str()
        .ok_or_else(|| crate::Error::Provider("slack: no socket url".into()))?;
    let (socket, _) = tungstenite::connect(url)
        .map_err(|e| crate::Error::Provider(format!("slack socket: {e}")))?;
    if let MaybeTlsStream::Rustls(s) = socket.get_ref() {
        let _ = s.get_ref().set_read_timeout(Some(Duration::from_secs(15)));
    } else if let MaybeTlsStream::Plain(s) = socket.get_ref() {
        let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    }
    Ok(socket)
}

impl SlackAdapter {
    pub fn connect(
        credential_json: &str,
        allowed_channels: Vec<String>,
    ) -> Result<Self, crate::Error> {
        let cred: Value = serde_json::from_str(credential_json).map_err(|_| {
            crate::Error::Provider(
                "slack credential must be JSON: {\"app_token\":\"xapp-…\",\"bot_token\":\"xoxb-…\"}"
                    .into(),
            )
        })?;
        let get = |k: &str| {
            cred.get(k)
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| crate::Error::Provider(format!("slack credential missing {k}")))
        };
        let app_token = get("app_token")?;
        let bot_token = get("bot_token")?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| crate::Error::Provider(format!("slack client: {e}")))?;
        let auth: Value = http
            .post("https://slack.com/api/auth.test")
            .bearer_auth(&bot_token)
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("slack auth.test: {e}")))?;
        if auth["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "slack refused the bot token: {}",
                auth["error"].as_str().unwrap_or("unknown")
            )));
        }
        let bot_user_id = auth["user_id"].as_str().unwrap_or_default().to_string();
        let socket = open_socket(&http, &app_token)?;
        Ok(Self {
            http,
            app_token,
            bot_token,
            rules: SlackRules {
                bot_user_id,
                allowed_channels,
                seen: std::collections::VecDeque::new(),
            },
            socket,
        })
    }
}

impl SlackRules {
    fn channel_allowed(&self, channel: &str) -> bool {
        self.allowed_channels.is_empty()
            || self
                .allowed_channels
                .iter()
                .any(|c| c == "*" || c == channel)
    }

    fn remember(&mut self, id: &str) -> bool {
        if self.seen.iter().any(|s| s == id) {
            return false;
        }
        if self.seen.len() >= 64 {
            self.seen.pop_front();
        }
        self.seen.push_back(id.to_string());
        true
    }

    /// Does this Events API payload engage the agent? DMs always;
    /// channels on app_mention.
    fn extract(&mut self, payload: &Value) -> Option<crate::presence::Mention> {
        let event = &payload["event"];
        let etype = event["type"].as_str().unwrap_or_default();
        let user = event["user"].as_str().unwrap_or_default();
        if user.is_empty() || user == self.bot_user_id || event["bot_id"].is_string() {
            return None; // never react to bots or ourselves
        }
        let channel = event["channel"].as_str().unwrap_or_default().to_string();
        let engages = match etype {
            "app_mention" => true,
            "message" => event["channel_type"].as_str() == Some("im"),
            _ => false,
        };
        if !engages || !self.channel_allowed(&channel) {
            return None;
        }
        let event_id = payload["event_id"].as_str().unwrap_or_default();
        if !event_id.is_empty() && !self.remember(event_id) {
            return None; // redelivery of an event we already handled
        }
        let text = event["text"].as_str().unwrap_or_default().to_string();
        // Thread the reply where the mention lives.
        let thread_ts = event["thread_ts"]
            .as_str()
            .or_else(|| event["ts"].as_str())
            .unwrap_or_default()
            .to_string();
        Some(crate::presence::Mention {
            channel,
            author: user.to_string(),
            text,
            reply_ref: thread_ts,
            attachments: Vec::new(), // filled by the adapter after extract
        })
    }
}

/// Download image and audio files from a Slack event (url_private + bot bearer),
/// size-capped; failures skip the file, never the mention.
fn fetch_slack_images(
    http: &reqwest::blocking::Client,
    bot_token: &str,
    event: &Value,
) -> Vec<crate::presence::Attachment> {
    const MAX_BYTES: u64 = crate::presence::MAX_ATTACHMENT_BYTES;
    let mut out = Vec::new();
    for f in event["files"].as_array().cloned().unwrap_or_default() {
        let mime = f["mimetype"].as_str().unwrap_or_default().to_string();
        let is_image = mime.starts_with("image/");
        let is_audio = mime.starts_with("audio/")
            || mime == "video/webm" && f["subtype"].as_str() == Some("slack_audio");
        if !(is_image || is_audio) || f["size"].as_u64().unwrap_or(0) > MAX_BYTES {
            continue;
        }
        let Some(url) = f["url_private"].as_str() else {
            continue;
        };
        let Ok(resp) = http.get(url).bearer_auth(bot_token).send() else {
            continue;
        };
        let Ok(bytes) = resp.bytes() else { continue };
        if bytes.len() as u64 > MAX_BYTES {
            continue;
        }
        use base64::Engine;
        let base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        out.push(if is_image {
            crate::presence::Attachment::Image {
                media_type: mime,
                base64,
            }
        } else {
            crate::presence::Attachment::Audio {
                media_type: if mime == "video/webm" {
                    "audio/webm".into()
                } else {
                    mime
                },
                base64,
                duration_secs: f["duration_ms"].as_f64().map(|d| (d / 1000.0) as f32),
            }
        });
        if out.len() >= crate::presence::MAX_ATTACHMENTS {
            break;
        }
    }
    out
}

impl crate::presence::ChannelAdapter for SlackAdapter {
    fn kind(&self) -> &'static str {
        "slack"
    }

    fn describe(&self) -> String {
        format!(
            "slack: socket mode as {} ({})",
            self.rules.bot_user_id,
            if self.rules.allowed_channels.is_empty() {
                "all installed channels".to_string()
            } else {
                format!("{} allowed channels", self.rules.allowed_channels.len())
            }
        )
    }

    fn next_mention(
        &mut self,
        stop: &AtomicBool,
    ) -> Result<Option<crate::presence::Mention>, crate::Error> {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let frame = match self.socket.read() {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Ping(p)) => {
                let _ = self.socket.send(Message::Pong(p));
                return Ok(None);
            }
            Ok(_) => return Ok(None),
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Quiet interval — tick (lease heartbeats happen here).
                let _ = self.socket.send(Message::Ping(Vec::new().into()));
                return Ok(None);
            }
            Err(_) => {
                // Dropped socket (Slack rotates them): reopen.
                for _ in 0..5 {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                if let Ok(fresh) = open_socket(&self.http, &self.app_token) {
                    self.socket = fresh;
                }
                return Ok(None);
            }
        };
        let v: Value = match serde_json::from_str(&frame) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        match v["type"].as_str().unwrap_or_default() {
            "disconnect" => {
                // Slack asks us to move to a fresh socket.
                if let Ok(fresh) = open_socket(&self.http, &self.app_token) {
                    self.socket = fresh;
                }
                Ok(None)
            }
            "events_api" => {
                // Ack FIRST — the governed run may take seconds and Slack
                // redelivers unacked envelopes aggressively.
                if let Some(envelope_id) = v["envelope_id"].as_str() {
                    let _ = self.socket.send(Message::Text(
                        json!({"envelope_id": envelope_id}).to_string().into(),
                    ));
                }
                let mut mention = self.rules.extract(&v["payload"]);
                if let Some(m) = mention.as_mut() {
                    m.attachments =
                        fetch_slack_images(&self.http, &self.bot_token, &v["payload"]["event"]);
                }
                Ok(mention)
            }
            _ => Ok(None), // hello etc.
        }
    }

    fn reply(
        &mut self,
        mention: &crate::presence::Mention,
        text: &str,
    ) -> Result<String, crate::Error> {
        let resp: Value = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.bot_token)
            .json(&json!({
                "channel": mention.channel,
                "text": text,
                "thread_ts": mention.reply_ref,
            }))
            .send()
            .and_then(|r| r.json())
            .map_err(|e| crate::Error::Provider(format!("slack postMessage: {e}")))?;
        if resp["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "slack postMessage refused: {}",
                resp["error"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(resp["ts"].as_str().unwrap_or_default().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> SlackRules {
        SlackRules {
            bot_user_id: "U_BOT".into(),
            allowed_channels: vec!["C1".into()],
            seen: Default::default(),
        }
    }

    #[test]
    fn mentions_and_dms_engage_channels_gate() {
        let mut a = adapter();
        // app_mention in an allowed channel engages
        let m = a.extract(&json!({"event_id": "E1", "event": {
            "type": "app_mention", "user": "U1", "channel": "C1",
            "text": "<@U_BOT> hi", "ts": "1.0"}}));
        assert!(m.is_some());
        // same event id redelivered: dropped
        assert!(a
            .extract(&json!({"event_id": "E1", "event": {
                "type": "app_mention", "user": "U1", "channel": "C1",
                "text": "<@U_BOT> hi", "ts": "1.0"}}))
            .is_none());
        // disallowed channel: dropped
        assert!(a
            .extract(&json!({"event_id": "E2", "event": {
                "type": "app_mention", "user": "U1", "channel": "C9",
                "text": "hi", "ts": "1.0"}}))
            .is_none());
        // DM engages
        assert!(a
            .extract(&json!({"event_id": "E3", "event": {
                "type": "message", "channel_type": "im", "user": "U1",
                "channel": "C1", "text": "hi", "ts": "2.0"}}))
            .is_some());
        // bot-authored: never
        assert!(a
            .extract(&json!({"event_id": "E4", "event": {
                "type": "app_mention", "user": "U_BOT", "channel": "C1",
                "text": "hi", "ts": "3.0"}}))
            .is_none());
    }
}
