use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::Result;
use crate::identity::NostrKeypair;
use crate::nostr::{random_nonce, xor_stream_encrypt};

pub fn encrypt(
    sender: &NostrKeypair,
    receiver_pubkey_hex: &str,
    plaintext: &str,
) -> Result<String> {
    let iv = random_nonce::<16>();
    let ciphertext = xor_stream_encrypt(
        &sender.secret_key(),
        receiver_pubkey_hex,
        &iv,
        plaintext.as_bytes(),
    )?;
    Ok(format!(
        "{}?iv={}",
        STANDARD.encode(ciphertext),
        hex::encode(iv)
    ))
}

pub fn decrypt(receiver: &NostrKeypair, sender_pubkey_hex: &str, content: &str) -> Result<String> {
    let (ciphertext, iv_hex) = content.split_once("?iv=").unwrap_or((content, ""));
    let iv = hex::decode(iv_hex)?;
    let decoded = STANDARD.decode(ciphertext)?;
    let plaintext = xor_stream_encrypt(&receiver.secret_key(), sender_pubkey_hex, &iv, &decoded)?;
    Ok(String::from_utf8(plaintext)?)
}
