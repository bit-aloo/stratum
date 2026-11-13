use crate::{
    Certificate, CertifiedStaticKey, Error, Initiator, InitiatorAuthentication, NoiseEngine,
    Responder, ResponderIdentity, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE,
};
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::{Keypair, Secp256k1};

fn key(rng: &mut StdRng) -> Keypair {
    Keypair::new(&Secp256k1::new(), rng)
}

fn handshake(
    identity: &ResponderIdentity,
    authentication: InitiatorAuthentication,
    now: u32,
    rng: &mut StdRng,
) -> Result<
    (
        NoiseEngine,
        NoiseEngine,
        [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE],
    ),
    Error,
> {
    let mut initiator = Initiator::new_with_rng(authentication, rng);
    let mut responder = Responder::new_with_rng(identity, rng);
    let first = initiator.step_0()?;
    let (second, responder_engine) = responder.step_1_with_now_rng(first, now, rng)?;
    let initiator_engine = initiator.step_2_with_now(second, now)?;
    Ok((initiator_engine, responder_engine, second))
}

fn round_trip(initiator: &mut NoiseEngine, responder: &mut NoiseEngine) {
    let mut message = b"initiator to responder".to_vec();
    initiator.encrypt(&mut message).unwrap();
    responder.decrypt(&mut message).unwrap();
    assert_eq!(message, b"initiator to responder");
    let mut message = b"responder to initiator".to_vec();
    responder.encrypt(&mut message).unwrap();
    initiator.decrypt(&mut message).unwrap();
    assert_eq!(message, b"responder to initiator");
}

#[test]
#[cfg_attr(miri, ignore)]
fn all_identity_and_authentication_combinations() {
    let mut rng = StdRng::seed_from_u64(42);
    let authority = key(&mut rng);
    let wrong_authority = key(&mut rng);
    let static_key = key(&mut rng);
    let certificate = Certificate::issue_with_rng(
        &static_key.x_only_public_key().0,
        &authority,
        100,
        200,
        &mut rng,
    )
    .unwrap();
    let identities = [
        ResponderIdentity::Unauthenticated,
        ResponderIdentity::Authority {
            authority,
            certificate_validity: 60,
        },
        ResponderIdentity::Certified(
            CertifiedStaticKey::new(static_key, certificate, &authority.x_only_public_key().0)
                .unwrap(),
        ),
    ];
    let policies = [
        InitiatorAuthentication::Unauthenticated,
        InitiatorAuthentication::Authority(authority.x_only_public_key().0),
        InitiatorAuthentication::Authority(wrong_authority.x_only_public_key().0),
    ];
    for (identity_index, identity) in identities.iter().enumerate() {
        for (policy_index, policy) in policies.iter().enumerate() {
            let result = handshake(identity, *policy, 150, &mut rng);
            if policy_index == 0 || (policy_index == 1 && identity_index != 0) {
                let (mut initiator, mut responder, _) = result.unwrap();
                round_trip(&mut initiator, &mut responder);
            } else {
                assert!(matches!(result, Err(Error::InvalidCertificate(_))));
            }
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn certified_identity_is_reusable_with_fresh_ephemerals() {
    let mut rng = StdRng::seed_from_u64(7);
    let authority = key(&mut rng);
    let static_key = key(&mut rng);
    let authority_pk = authority.x_only_public_key().0;
    let certificate = Certificate::issue_with_rng(
        &static_key.x_only_public_key().0,
        &authority,
        100,
        200,
        &mut rng,
    )
    .unwrap();
    let identity = ResponderIdentity::Certified(
        CertifiedStaticKey::new(static_key, certificate, &authority_pk).unwrap(),
    );
    let mut previous_ephemeral = None;
    for _ in 0..3 {
        let (mut initiator, mut responder, response) = handshake(
            &identity,
            InitiatorAuthentication::Authority(authority_pk),
            150,
            &mut rng,
        )
        .unwrap();
        round_trip(&mut initiator, &mut responder);
        assert_ne!(previous_ephemeral.as_deref(), Some(&response[..64]));
        previous_ephemeral = Some(response[..64].to_vec());
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn expired_certificate_is_sent_verbatim_and_rejected_by_authenticated_initiator() {
    let mut rng = StdRng::seed_from_u64(10);
    let authority = key(&mut rng);
    let static_key = key(&mut rng);
    let authority_pk = authority.x_only_public_key().0;
    let certificate = Certificate::issue_with_rng(
        &static_key.x_only_public_key().0,
        &authority,
        100,
        200,
        &mut rng,
    )
    .unwrap();
    let encoded = certificate.to_bytes();
    let identity = ResponderIdentity::Certified(
        CertifiedStaticKey::new(static_key, certificate, &authority_pk).unwrap(),
    );
    for now in [89, 211] {
        match handshake(
            &identity,
            InitiatorAuthentication::Authority(authority_pk),
            now,
            &mut rng,
        ) {
            Err(Error::InvalidCertificate(received)) => assert_eq!(received.to_bytes(), encoded),
            _ => panic!("out-of-window certificate must be rejected"),
        }
    }
    // Choosing unauthenticated operation skips certificate authentication and time checks.
    let (mut initiator, mut responder, _) = handshake(
        &identity,
        InitiatorAuthentication::Unauthenticated,
        211,
        &mut rng,
    )
    .unwrap();
    round_trip(&mut initiator, &mut responder);
}

#[test]
#[cfg_attr(miri, ignore)]
fn credential_pairing_rejects_wrong_keys_and_modified_certificates() {
    let mut rng = StdRng::seed_from_u64(11);
    let authority = key(&mut rng);
    let static_key = key(&mut rng);
    let wrong_key = key(&mut rng);
    let authority_pk = authority.x_only_public_key().0;
    let certificate = Certificate::issue_with_rng(
        &static_key.x_only_public_key().0,
        &authority,
        100,
        200,
        &mut rng,
    )
    .unwrap();
    assert!(matches!(
        CertifiedStaticKey::new(wrong_key, certificate.clone(), &authority_pk),
        Err(Error::InvalidCertificate(_))
    ));
    assert!(matches!(
        CertifiedStaticKey::new(
            static_key,
            certificate.clone(),
            &wrong_key.x_only_public_key().0
        ),
        Err(Error::InvalidCertificate(_))
    ));
    for index in [0, 2, 6, 10, 73] {
        let mut bytes = certificate.to_bytes();
        bytes[index] ^= 1;
        assert!(matches!(
            CertifiedStaticKey::new(static_key, bytes.into(), &authority_pk),
            Err(Error::InvalidCertificate(_))
        ));
    }
}
