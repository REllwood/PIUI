use crate::domain::update_state::{
    UpdateState, UpdateStatus, valid_public_key, valid_update_endpoint,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const MAX_LOCAL_UPDATE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct UpdateConfiguration {
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
    pub automatic_checks: bool,
}

impl UpdateConfiguration {
    pub fn state(&self) -> UpdateState {
        UpdateState {
            status: UpdateStatus::Disabled,
            endpoint: self.endpoint.clone(),
            public_key: self.public_key.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.automatic_checks {
            return Err("automatic-updates-disabled".into());
        }
        if self.endpoint.is_none() && self.public_key.is_none() {
            return Ok(());
        }
        let (Some(endpoint), Some(public_key)) = (&self.endpoint, &self.public_key) else {
            return Err("update-prerequisites-incomplete".into());
        };
        if !valid_update_endpoint(endpoint) || !valid_public_key(public_key) {
            return Err("update-prerequisites-invalid".into());
        }
        Ok(())
    }
}

pub fn verify_local_fixture(payload: &[u8], expected_sha256: &[u8; 32]) -> bool {
    Sha256::digest(payload).as_slice() == expected_sha256
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    pub sha256: [u8; 32],
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaunchHandoff {
    pub verified_sha256: [u8; 32],
    pub next_generation: u64,
}

pub fn verify_signed_local_fixture(
    payload: &[u8],
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<VerifiedUpdate, String> {
    if payload.is_empty() || payload.len() > MAX_LOCAL_UPDATE_BYTES {
        return Err("update-payload-invalid".into());
    }
    let public_key = decode_hex::<32>(public_key_hex).ok_or("update-public-key-invalid")?;
    let signature = decode_hex::<64>(signature_hex).ok_or("update-signature-invalid")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| "update-public-key-invalid")?;
    let signature = Signature::from_bytes(&signature);
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| "update-verification-failed")?;
    Ok(VerifiedUpdate {
        sha256: Sha256::digest(payload).into(),
        bytes: payload.len(),
    })
}

pub fn prepare_relaunch_handoff(
    update: &VerifiedUpdate,
    explicit_user_action: bool,
    current_generation: u64,
) -> Result<RelaunchHandoff, String> {
    if !explicit_user_action {
        return Err("update-user-action-required".into());
    }
    let next_generation = current_generation
        .checked_add(1)
        .ok_or("update-generation-exhausted")?;
    Ok(RelaunchHandoff {
        verified_sha256: update.sha256,
        next_generation,
    })
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? || !value.is_ascii() {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let start = index.checked_mul(2)?;
        *byte = u8::from_str_radix(value.get(start..start + 2)?, 16).ok()?;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::{UpdateConfiguration, prepare_relaunch_handoff, verify_signed_local_fixture};

    const RFC_8032_PUBLIC_KEY: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC_8032_SIGNATURE: &str = concat!(
        "92a009a9f0d4cab8720e820b5f642540",
        "a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c",
        "387b2eaeb4302aeeb00d291612bb0c00",
    );

    #[test]
    fn update_configuration_is_disabled_safe_and_rejects_ambiguous_endpoints() {
        assert!(UpdateConfiguration::default().validate().is_ok());
        assert_eq!(
            UpdateConfiguration {
                automatic_checks: true,
                ..UpdateConfiguration::default()
            }
            .validate(),
            Err("automatic-updates-disabled".into())
        );
        for endpoint in [
            "http://updates.example.test/latest.json",
            "https://user@example.test/latest.json",
            "https://example.test/latest.json#unsigned-fragment",
        ] {
            assert!(
                UpdateConfiguration {
                    endpoint: Some(endpoint.into()),
                    public_key: Some(RFC_8032_PUBLIC_KEY.into()),
                    automatic_checks: false,
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            UpdateConfiguration {
                endpoint: Some("https://updates.example.test/piui/latest.json".into()),
                public_key: Some(RFC_8032_PUBLIC_KEY.into()),
                automatic_checks: false,
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn signed_fixture_requires_exact_ed25519_signature() {
        let verified =
            verify_signed_local_fixture(&[0x72], RFC_8032_PUBLIC_KEY, RFC_8032_SIGNATURE)
                .expect("RFC 8032 fixture should verify");
        assert_eq!(verified.bytes, 1);

        assert_eq!(
            verify_signed_local_fixture(&[0x73], RFC_8032_PUBLIC_KEY, RFC_8032_SIGNATURE,),
            Err("update-verification-failed".into())
        );
        assert!(verify_signed_local_fixture(&[0x72], "00", RFC_8032_SIGNATURE).is_err());
        assert!(verify_signed_local_fixture(&[0x72], RFC_8032_PUBLIC_KEY, "00").is_err());
    }

    #[test]
    fn relaunch_handoff_requires_user_action_and_advances_once() {
        let verified =
            verify_signed_local_fixture(&[0x72], RFC_8032_PUBLIC_KEY, RFC_8032_SIGNATURE).unwrap();
        assert_eq!(
            prepare_relaunch_handoff(&verified, false, 7),
            Err("update-user-action-required".into())
        );
        let handoff = prepare_relaunch_handoff(&verified, true, 7).unwrap();
        assert_eq!(handoff.next_generation, 8);
        assert_eq!(handoff.verified_sha256, verified.sha256);
        assert!(prepare_relaunch_handoff(&verified, true, u64::MAX).is_err());
    }
}
