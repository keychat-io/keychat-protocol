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
pub fn build_lightning_message(
    invoice: &str,
    amount: u64,
    memo: Option<&str>,
) -> KCMessage {
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
pub fn attach_ecash_stamp(event: &Event, ecash_token: &str) -> String {
    let event_json = serde_json::to_value(event).unwrap();
    let arr = serde_json::json!(["EVENT", event_json, ecash_token]);
    arr.to_string()
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
        let msg = build_cashu_message(
            "https://mint.example.com",
            "cashuAtoken",
            50,
            None,
            None,
        );
        let parsed = KCMessage::try_parse(&msg.to_json().unwrap()).unwrap();
        let cashu = parsed.cashu.unwrap();
        assert!(cashu.unit.is_none());
        assert!(cashu.memo.is_none());
    }

    #[test]
    fn build_lightning_message_has_invoice() {
        let msg = build_lightning_message(
            "lnbc1pvjluezsp5zyg3zyg3zyg3zyg",
            1000,
            Some("Pay me"),
        );
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
    fn attach_ecash_stamp_correct_format() {
        use nostr::Keys;

        // Create a minimal event for testing
        let keys = Keys::generate();
        let event = nostr::EventBuilder::text_note("test")
            .sign_with_keys(&keys)
            .unwrap();

        let token = "cashuAeyJhbGciOiJIUzI1NiJ9";
        let result = attach_ecash_stamp(&event, token);

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
