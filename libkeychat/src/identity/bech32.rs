use bech32::{Bech32, Hrp};

use crate::error::{KeychatError, Result};

const KEY_LEN: usize = 32;

pub fn encode_npub(public_key: &[u8; KEY_LEN]) -> Result<String> {
    encode_with_hrp("npub", public_key)
}

pub fn decode_npub(value: &str) -> Result<[u8; KEY_LEN]> {
    decode_with_hrp("npub", value)
}

pub fn encode_nsec(secret_key: &[u8; KEY_LEN]) -> Result<String> {
    encode_with_hrp("nsec", secret_key)
}

pub fn decode_nsec(value: &str) -> Result<[u8; KEY_LEN]> {
    decode_with_hrp("nsec", value)
}

fn encode_with_hrp(hrp: &'static str, bytes: &[u8; KEY_LEN]) -> Result<String> {
    Ok(bech32::encode::<Bech32>(Hrp::parse(hrp)?, bytes)?)
}

fn decode_with_hrp(expected_hrp: &'static str, value: &str) -> Result<[u8; KEY_LEN]> {
    let (hrp, bytes) = bech32::decode(value)?;
    if hrp != Hrp::parse(expected_hrp)? {
        return Err(KeychatError::InvalidHrp {
            expected: expected_hrp,
            found: hrp.to_string(),
        });
    }
    if bytes.len() != KEY_LEN {
        return Err(KeychatError::InvalidLength {
            expected: KEY_LEN,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}
