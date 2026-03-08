use crate::error::{KeychatError, Result};
use crate::identity::NostrKeypair;
use crate::nostr::nip44;
use crate::nostr::{generate_ephemeral_sender, now, NostrEvent};

pub fn create_gift_wrap(
    sender: &NostrKeypair,
    receiver_pubkey_hex: &str,
    inner_kind: u16,
    content: String,
    additional_tags: Vec<Vec<String>>,
) -> Result<NostrEvent> {
    let mut rumor_tags = additional_tags;
    if rumor_tags.is_empty() {
        rumor_tags.push(vec!["p".to_owned(), receiver_pubkey_hex.to_owned()]);
    }

    let rumor = NostrEvent::new_rumor(
        sender.public_key_hex(),
        inner_kind,
        rumor_tags,
        content,
        now(),
    );

    let seal_content =
        nip44::encrypt(sender, receiver_pubkey_hex, &serde_json::to_string(&rumor)?)?;
    let seal = NostrEvent::new_unsigned(
        sender.public_key_hex(),
        13,
        vec![vec!["p".to_owned(), receiver_pubkey_hex.to_owned()]],
        seal_content,
        now(),
    )
    .sign(sender)?;

    let ephemeral = generate_ephemeral_sender();
    let gift_content = nip44::encrypt(
        &ephemeral,
        receiver_pubkey_hex,
        &serde_json::to_string(&seal)?,
    )?;
    NostrEvent::new_unsigned(
        ephemeral.public_key_hex(),
        1059,
        vec![vec!["p".to_owned(), receiver_pubkey_hex.to_owned()]],
        gift_content,
        now(),
    )
    .sign(&ephemeral)
}

pub fn unwrap_gift_wrap(receiver: &NostrKeypair, gift: &NostrEvent) -> Result<NostrEvent> {
    if gift.kind != 1059 {
        return Err(KeychatError::InvalidEventKind {
            expected: 1059,
            actual: gift.kind,
        });
    }
    gift.verify()?;

    let seal_json = nip44::decrypt(receiver, &gift.pubkey, &gift.content)?;
    let seal: NostrEvent = serde_json::from_str(&seal_json)?;
    seal.verify()?;

    let rumor_json = nip44::decrypt(receiver, &seal.pubkey, &seal.content)?;
    let rumor: NostrEvent = serde_json::from_str(&rumor_json)?;
    rumor.verify_id()?;
    Ok(rumor)
}
