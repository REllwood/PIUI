use piui_lib::updates::{
    UpdateConfiguration, prepare_relaunch_handoff, verify_signed_local_fixture,
};

const PUBLIC_KEY: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const SIGNATURE: &str = concat!(
    "92a009a9f0d4cab8720e820b5f642540",
    "a2b27b5416503f8fb3762223ebdb69da",
    "085ac1e43e15996e458f3613d0f11d8c",
    "387b2eaeb4302aeeb00d291612bb0c00",
);

#[test]
fn disabled_configuration_makes_no_activation_claim() {
    let configuration = UpdateConfiguration::default();
    assert!(configuration.validate().is_ok());
    assert!(!configuration.state().activated());
}

#[test]
fn only_a_verified_fixture_can_enter_explicit_relaunch_handoff() {
    let verified = verify_signed_local_fixture(&[0x72], PUBLIC_KEY, SIGNATURE).unwrap();
    assert!(prepare_relaunch_handoff(&verified, false, 3).is_err());
    let handoff = prepare_relaunch_handoff(&verified, true, 3).unwrap();
    assert_eq!(handoff.next_generation, 4);
    assert_eq!(handoff.verified_sha256, verified.sha256);
    assert!(verify_signed_local_fixture(&[0x73], PUBLIC_KEY, SIGNATURE).is_err());
}
