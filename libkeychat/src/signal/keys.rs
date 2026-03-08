use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKeyPair, KeyPair, PreKeyBundle, PreKeyId, PreKeyRecord,
    SignedPreKeyId, SignedPreKeyRecord,
};
use rand::{rngs::OsRng, Rng};

use crate::error::Result;

#[derive(Clone)]
pub struct SignalPreKeyMaterial {
    pub identity_key_pair: IdentityKeyPair,
    pub registration_id: u32,
    pub signed_prekey_id: SignedPreKeyId,
    pub signed_prekey: SignedPreKeyRecord,
    pub prekey_id: PreKeyId,
    pub prekey: PreKeyRecord,
}

impl SignalPreKeyMaterial {
    pub fn build_prekey_bundle(&self, device_id: DeviceId) -> Result<PreKeyBundle> {
        Ok(PreKeyBundle::new(
            self.registration_id,
            device_id,
            Some((self.prekey_id, self.prekey.public_key()?)),
            self.signed_prekey_id,
            self.signed_prekey.public_key()?,
            self.signed_prekey.signature()?,
            *self.identity_key_pair.identity_key(),
        )?)
    }
}

pub fn generate_prekey_material() -> Result<SignalPreKeyMaterial> {
    let mut rng = OsRng;
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let registration_id = rand::thread_rng().gen_range(1..=u32::MAX);

    let signed_prekey_id = SignedPreKeyId::from(1);
    let signed_prekey_key_pair = KeyPair::generate(&mut rng);
    let signed_prekey_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_prekey_key_pair.public_key.serialize(), &mut rng)?;
    let signed_prekey = <SignedPreKeyRecord as GenericSignedPreKey>::new(
        signed_prekey_id,
        timestamp_now(),
        &signed_prekey_key_pair,
        &signed_prekey_signature,
    );

    let prekey_id = PreKeyId::from(1);
    let prekey_key_pair = KeyPair::generate(&mut rng);
    let prekey = PreKeyRecord::new(prekey_id, &prekey_key_pair);

    Ok(SignalPreKeyMaterial {
        identity_key_pair,
        registration_id,
        signed_prekey_id,
        signed_prekey,
        prekey_id,
        prekey,
    })
}

fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
