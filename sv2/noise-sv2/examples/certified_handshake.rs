//! Offline issuance followed by an authenticated handshake using only certified server credentials.
use noise_sv2::{
    Certificate, CertifiedStaticKey, Initiator, InitiatorAuthentication, Responder,
    ResponderIdentity,
};
use secp256k1::{Keypair, Secp256k1};

fn main() {
    let mut rng = rand::thread_rng();
    let secp = Secp256k1::new();
    let static_key = Keypair::new(&secp, &mut rng);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    // This block represents a separate issuer. Only the server's public key is needed to issue.
    let (authority_pk, certificate_bytes) = {
        let mut authority = Keypair::new(&secp, &mut rng);
        let certificate = Certificate::issue_with_rng(
            &static_key.x_only_public_key().0,
            &authority,
            now,
            now.saturating_add(3600),
            &mut rng,
        )
        .unwrap();
        let authority_pk = authority.x_only_public_key().0;
        authority.non_secure_erase();
        (authority_pk, certificate.to_bytes())
    };

    let credentials = CertifiedStaticKey::new(static_key, certificate_bytes.into(), &authority_pk)
        .expect("certificate must cover this server's static key");
    let identity = ResponderIdentity::Certified(credentials);
    let mut responder = Responder::new_with_rng(&identity, &mut rng);
    let mut initiator =
        Initiator::new_with_rng(InitiatorAuthentication::Authority(authority_pk), &mut rng);
    let first = initiator.step_0().unwrap();
    let (second, mut server) = responder.step_1_with_now_rng(first, now, &mut rng).unwrap();
    let mut client = initiator.step_2_with_now(second, now).unwrap();
    let mut message = b"certified connection".to_vec();
    client.encrypt(&mut message).unwrap();
    server.decrypt(&mut message).unwrap();
    assert_eq!(message, b"certified connection");
}
