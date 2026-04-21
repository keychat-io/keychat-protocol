//! Payment message helpers (§13 Ecash Stamps, Lightning).
//!
//! Builders for Cashu ecash and Lightning invoice KCMessages,
//! plus ecash stamp formatting for relay delivery.

use crate::message::{KCCashuPayload, KCLightningPayload, KCMessage, KCMessageKind};
use crate::Result;
use nostr::Event;

// ─── Builders ───────────────────────────────────────────────────────────────

/// Build a Cashu ecash message.
pub fn build_cashu_message(
    mint: &str,
    token: &str,
    amount: u64,
    unit: Option<&str>,
    memo: Option<&str>,
) -> KCMessage {
    KCMessage {
        v: 2,
        id: Some(crate::message::uuid_v4()),
        kind: KCMessageKind::Cashu,
        cashu: Some(KCCashuPayload {
            mint: mint.to_string(),
            token: token.to_string(),
            amount,
            unit: unit.map(|s| s.to_string()),
            memo: memo.map(|s| s.to_string()),
            message: None,
        }),
        ..KCMessage::empty()
    }
}

/// Build a Lightning invoice message.
pub fn build_lightning_message(invoice: &str, amount: u64, memo: Option<&str>) -> KCMessage {
    KCMessage {
        v: 2,
        id: Some(crate::message::uuid_v4()),
        kind: KCMessageKind::LightningInvoice,
        lightning: Some(KCLightningPayload {
            invoice: invoice.to_string(),
            amount,
            mint: None,
            hash: None,
            message: memo.map(|s| s.to_string()),
        }),
        ..KCMessage::empty()
    }
}

/// Build a red packet message with N pre-minted independent tokens.
/// Receivers try each token in order; mint's double-spend protection gives
/// first-come-first-served semantics.
pub fn build_red_packet_message(
    mint: &str,
    tokens: Vec<String>,
    total_amount: u64,
    count: u32,
    memo: Option<&str>,
) -> KCMessage {
    use crate::message::{KCRedPacketPayload, uuid_v4};
    KCMessage {
        v: 2,
        id: Some(uuid_v4()),
        kind: KCMessageKind::RedPacket,
        red_packet: Some(KCRedPacketPayload {
            mint: mint.to_string(),
            tokens,
            total_amount,
            count,
            memo: memo.map(|s| s.to_string()),
        }),
        ..KCMessage::empty()
    }
}

/// Split a total amount into N roughly-equal shares. Remainder goes to last share.
pub fn split_red_packet_equal(total: u64, count: u32) -> Vec<u64> {
    if count == 0 { return vec![]; }
    let base = total / count as u64;
    let remainder = total % count as u64;
    let mut shares = vec![base; count as usize];
    if let Some(last) = shares.last_mut() { *last += remainder; }
    shares
}

// ─── Cashu Token Validation ─────────────────────────────────────────────────

/// Parse a Cashu token string, validate format (must start with "cashuA").
pub fn validate_cashu_token(token: &str) -> Result<()> {
    if !token.starts_with("cashuA") {
        return Err(crate::KeychatError::MediaCrypto(
            "Invalid Cashu token: must start with 'cashuA'".into(),
        ));
    }
    if token.len() < 10 {
        return Err(crate::KeychatError::MediaCrypto(
            "Invalid Cashu token: too short".into(),
        ));
    }
    Ok(())
}

// ─── Ecash Stamp ────────────────────────────────────────────────────────────

/// Ecash stamp helper: format the EVENT+stamp tuple for relay delivery.
///
/// Returns the JSON array: `["EVENT", <event_json>, <ecash_token>]`
///
/// Per §13.1, the ecash token is appended as a third element to the standard
/// Nostr `["EVENT", <event>]` message for relay consumption.
pub fn attach_ecash_stamp(event: &Event, ecash_token: &str) -> Result<String> {
    let event_json =
        serde_json::to_value(event).map_err(|e| crate::KeychatError::Serialization(e))?;
    let arr = serde_json::json!(["EVENT", event_json, ecash_token]);
    Ok(arr.to_string())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cashu_message_correct_fields() {
        let msg = build_cashu_message(
            "https://mint.example.com",
            "cashuAabc123token",
            100,
            Some("sat"),
            Some("Coffee money"),
        );
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::Cashu);
        let cashu = parsed.cashu.unwrap();
        assert_eq!(cashu.mint, "https://mint.example.com");
        assert_eq!(cashu.token, "cashuAabc123token");
        assert_eq!(cashu.amount, 100);
        assert_eq!(cashu.unit.as_deref(), Some("sat"));
        assert_eq!(cashu.memo.as_deref(), Some("Coffee money"));
    }

    #[test]
    fn build_cashu_message_no_optionals() {
        let msg = build_cashu_message("https://mint.example.com", "cashuAtoken", 50, None, None);
        let parsed = KCMessage::try_parse(&msg.to_json().unwrap()).unwrap();
        let cashu = parsed.cashu.unwrap();
        assert!(cashu.unit.is_none());
        assert!(cashu.memo.is_none());
    }

    #[test]
    fn build_lightning_message_has_invoice() {
        let msg = build_lightning_message("lnbc1pvjluezsp5zyg3zyg3zyg3zyg", 1000, Some("Pay me"));
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::LightningInvoice);
        let ln = parsed.lightning.unwrap();
        assert_eq!(ln.invoice, "lnbc1pvjluezsp5zyg3zyg3zyg3zyg");
        assert_eq!(ln.amount, 1000);
        assert_eq!(ln.message.as_deref(), Some("Pay me"));
    }

    #[test]
    fn validate_cashu_token_valid() {
        assert!(validate_cashu_token("cashuAeyJhbGciOiJIUzI1NiJ9").is_ok());
    }

    #[test]
    fn validate_cashu_token_invalid_prefix() {
        assert!(validate_cashu_token("notcashu").is_err());
    }

    #[test]
    fn validate_cashu_token_too_short() {
        assert!(validate_cashu_token("cashuA").is_err());
    }

    #[test]
    fn red_packet_message_roundtrip_json() {
        let msg = build_red_packet_message(
            "https://mint.example.com",
            vec!["cashuAtok1".into(), "cashuAtok2".into(), "cashuAtok3".into()],
            1000, 3, Some("Happy New Year"),
        );
        let json = msg.to_json().unwrap();
        assert!(json.contains("\"kind\":\"redPacket\""));
        assert!(json.contains("\"totalAmount\":1000"));
        assert!(json.contains("\"count\":3"));
        let decoded = KCMessage::try_parse(&json).unwrap();
        assert_eq!(decoded.kind, KCMessageKind::RedPacket);
        let rp = decoded.red_packet.unwrap();
        assert_eq!(rp.tokens.len(), 3);
        assert_eq!(rp.total_amount, 1000);
    }

    #[test]
    fn split_equal_no_remainder() {
        assert_eq!(split_red_packet_equal(1000, 10), vec![100u64; 10]);
    }

    #[test]
    fn split_equal_with_remainder() {
        let r = split_red_packet_equal(103, 10);
        assert_eq!(r.len(), 10);
        assert_eq!(r[..9].iter().sum::<u64>(), 90);
        assert_eq!(r[9], 13);
    }

    #[test]
    fn split_zero_count() {
        assert_eq!(split_red_packet_equal(1000, 0), Vec::<u64>::new());
    }

    #[test]
    fn attach_ecash_stamp_correct_format() {
        use nostr::Keys;

        // Create a minimal event for testing
        let keys = Keys::generate();
        let event = nostr::EventBuilder::text_note("test")
            .sign_with_keys(&keys)
            .unwrap();

        let token = "cashuAeyJhbGciOiJIUzI1NiJ9";
        let result = attach_ecash_stamp(&event, token).unwrap();

        // Parse the result as a JSON array
        let arr: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(arr.is_array());
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_str().unwrap(), "EVENT");
        assert!(arr[1].is_object()); // event JSON
        assert_eq!(arr[2].as_str().unwrap(), token);
    }
}
