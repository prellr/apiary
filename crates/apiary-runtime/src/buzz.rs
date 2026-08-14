//! Buzz membership — SPEC §3: "Buzz interop is structural, not a feature."
//!
//! Buzz IS a nostr relay, so an Apiary agent authenticates with the same
//! key that signs its log: NIP-42 challenge → signed kind-22242 response on
//! the same connection. Messages are Buzz's stream-message vocabulary:
//! kind 9 with an `["h", <channel-uuid>]` tag (see block/buzz
//! crates/buzz-sdk/src/builders.rs — the authoritative wire shape).
//!
//! NIP-42 auth is per-connection, so this is a session, not one-shot calls:
//! the socket that authenticated is the socket that posts and reads.

use apiary_core::custody::{AgentHandle, Custody};
use nostr::prelude::*;
use serde_json::{json, Value};
use std::net::TcpStream;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

/// Buzz stream message kind (NIP-29-style group chat).
pub const KIND_STREAM_MESSAGE: u16 = 9;
/// NIP-42 client auth kind.
pub const KIND_AUTH: u16 = 22242;
/// NIP-29 group/channel metadata kind (channel discovery).
pub const KIND_GROUP_METADATA: u16 = 39000;

pub struct BuzzSession<'a> {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    url: String,
    custody: &'a Custody,
    agent: &'a AgentHandle,
    authed: bool,
}

impl<'a> BuzzSession<'a> {
    pub fn connect(
        url: &str,
        custody: &'a Custody,
        agent: &'a AgentHandle,
    ) -> Result<Self, crate::Error> {
        let (socket, _) = tungstenite::connect(url)
            .map_err(|e| crate::Error::Provider(format!("connect {url}: {e}")))?;
        Ok(Self {
            socket,
            url: url.to_string(),
            custody,
            agent,
            authed: false,
        })
    }

    fn send(&mut self, frame: Value) -> Result<(), crate::Error> {
        self.socket
            .send(Message::Text(frame.to_string().into()))
            .map_err(|e| crate::Error::Provider(format!("send: {e}")))
    }

    fn recv(&mut self) -> Result<Value, crate::Error> {
        loop {
            let msg = self
                .socket
                .read()
                .map_err(|e| crate::Error::Provider(format!("read: {e}")))?;
            match msg {
                Message::Text(text) => return Ok(serde_json::from_str(&text)?),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(f) => {
                    return Err(crate::Error::Provider(format!("relay closed: {f:?}")))
                }
                _ => continue,
            }
        }
    }

    /// Answer a NIP-42 challenge on this connection: sign kind 22242 with
    /// the agent's own key — identity and relay auth are the same keypair,
    /// which is the whole point.
    fn auth(&mut self, challenge: &str) -> Result<(), crate::Error> {
        let builder = EventBuilder::new(Kind::Custom(KIND_AUTH), "")
            .tag(Tag::custom("relay", vec![self.url.clone()]))
            .tag(Tag::custom("challenge", vec![challenge.to_string()]));
        let event = self.custody.sign(self.agent, builder)?;
        self.send(json!([
            "AUTH",
            serde_json::from_str::<Value>(&event.as_json())?
        ]))?;
        // The relay replies OK <auth-event-id> true/false.
        for _ in 0..10 {
            let v = self.recv()?;
            match v.get(0).and_then(|t| t.as_str()) {
                Some("OK") if v.get(1).and_then(|i| i.as_str()) == Some(&event.id.to_hex()) => {
                    return if v.get(2).and_then(|b| b.as_bool()).unwrap_or(false) {
                        self.authed = true;
                        Ok(())
                    } else {
                        Err(crate::Error::Provider(format!(
                            "auth rejected: {}",
                            v.get(3).and_then(|m| m.as_str()).unwrap_or("")
                        )))
                    };
                }
                _ => continue,
            }
        }
        Err(crate::Error::Provider("no auth response".into()))
    }

    /// Publish an event, transparently answering an auth challenge once.
    pub fn publish(&mut self, event: &Event) -> Result<String, crate::Error> {
        for attempt in 0..2 {
            self.send(json!([
                "EVENT",
                serde_json::from_str::<Value>(&event.as_json())?
            ]))?;
            loop {
                let v = self.recv()?;
                match v.get(0).and_then(|t| t.as_str()) {
                    Some("AUTH") => {
                        let challenge = v
                            .get(1)
                            .and_then(|c| c.as_str())
                            .ok_or_else(|| crate::Error::Provider("bad AUTH frame".into()))?
                            .to_string();
                        self.auth(&challenge)?;
                        break; // retry the publish on the now-authed socket
                    }
                    Some("OK") if v.get(1).and_then(|i| i.as_str()) == Some(&event.id.to_hex()) => {
                        let accepted = v.get(2).and_then(|b| b.as_bool()).unwrap_or(false);
                        let detail = v.get(3).and_then(|m| m.as_str()).unwrap_or("").to_string();
                        if accepted || detail.starts_with("duplicate") {
                            return Ok(if detail.is_empty() {
                                "accepted".into()
                            } else {
                                detail
                            });
                        }
                        if detail.starts_with("auth-required") && attempt == 0 && !self.authed {
                            // Relay wants auth but didn't challenge yet; wait
                            // for its AUTH frame on the next loop turn.
                            continue;
                        }
                        return Err(crate::Error::Provider(format!("rejected: {detail}")));
                    }
                    _ => continue,
                }
            }
        }
        Err(crate::Error::Provider("publish failed after auth".into()))
    }

    /// REQ → events until EOSE, answering an auth challenge once.
    pub fn req(&mut self, filter: Value) -> Result<Vec<Event>, crate::Error> {
        for _attempt in 0..2 {
            let sub = "apiary-buzz";
            self.send(json!(["REQ", sub, filter]))?;
            let mut out = Vec::new();
            let mut reauth = false;
            for _ in 0..500 {
                let v = self.recv()?;
                match v.get(0).and_then(|t| t.as_str()) {
                    Some("AUTH") => {
                        let challenge = v
                            .get(1)
                            .and_then(|c| c.as_str())
                            .unwrap_or_default()
                            .to_string();
                        self.auth(&challenge)?;
                        reauth = true;
                        break;
                    }
                    Some("CLOSED") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        let why = v.get(2).and_then(|m| m.as_str()).unwrap_or("");
                        if why.starts_with("auth-required") && !self.authed {
                            // Wait for the relay's AUTH frame.
                            continue;
                        }
                        return Err(crate::Error::Provider(format!("closed: {why}")));
                    }
                    Some("EVENT") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        if let Some(raw) = v.get(2) {
                            if let Ok(event) = Event::from_json(raw.to_string()) {
                                if event.verify().is_ok() {
                                    out.push(event);
                                }
                            }
                        }
                    }
                    Some("EOSE") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                        return Ok(out)
                    }
                    _ => continue,
                }
            }
            if !reauth {
                break;
            }
        }
        Err(crate::Error::Provider("req failed".into()))
    }

    /// Build + sign + post a Buzz stream message to a channel.
    pub fn post(
        &mut self,
        channel_uuid: &str,
        content: &str,
        mention_hex: &[String],
    ) -> Result<Event, crate::Error> {
        let mut builder = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE), content)
            .tag(Tag::custom("h", vec![channel_uuid.to_string()]));
        for m in mention_hex {
            if let Ok(pk) = PublicKey::parse(m) {
                builder = builder.tag(Tag::public_key(pk));
            }
        }
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(event)
    }

    /// Read a channel's recent messages (kind 9, h-tagged).
    pub fn read_channel(
        &mut self,
        channel_uuid: &str,
        limit: usize,
    ) -> Result<Vec<Event>, crate::Error> {
        self.req(json!({
            "kinds": [KIND_STREAM_MESSAGE],
            "#h": [channel_uuid],
            "limit": limit,
        }))
    }

    /// Discover channels (NIP-29 group metadata).
    pub fn channels(&mut self) -> Result<Vec<Event>, crate::Error> {
        self.req(json!({"kinds": [KIND_GROUP_METADATA], "limit": 100}))
    }

    /// Publish the agent's kind-0 profile metadata (name/about/picture) —
    /// how the agent appears to humans in Buzz and every other nostr client.
    /// Replaceable: publishing again updates the profile.
    pub fn set_profile(
        &mut self,
        name: &str,
        about: Option<&str>,
        picture: Option<&str>,
    ) -> Result<Event, crate::Error> {
        let mut meta = json!({ "name": name });
        if let Some(a) = about {
            meta["about"] = json!(a);
        }
        if let Some(p) = picture {
            meta["picture"] = json!(p);
        }
        let builder = EventBuilder::new(Kind::Metadata, meta.to_string());
        let event = self.custody.sign(self.agent, builder)?;
        self.publish(&event)?;
        Ok(event)
    }
}
