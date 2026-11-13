use core::{convert::TryInto, fmt};

use secp256k1::{hashes::sha256, schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey};

use crate::{Error, CERTIFICATE_TIME_LEEWAY, CERTIFICATE_VERSION, SIGNATURE_NOISE_MESSAGE_SIZE};

/// The 74-byte `SIGNATURE_NOISE_MESSAGE` carried by the Noise handshake.
///
/// A certificate signs its version, validity window, and the responder's static public key.
/// Decoding bytes does not authenticate them; use [`Self::verify_with_now`] with the authority
/// public key. Use [`Self::issue_with_rng`] on the machine holding the authority private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    version: u16,
    valid_from: u32,
    not_valid_after: u32,
    signature: [u8; 64],
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Certificate {{ version: {}, valid_from: {}, not_valid_after: {}, signature: ",
            self.version, self.valid_from, self.not_valid_after
        )?;
        for byte in &self.signature {
            write!(f, "{byte:02x}")?;
        }
        write!(f, " }}")
    }
}

impl From<[u8; SIGNATURE_NOISE_MESSAGE_SIZE]> for Certificate {
    /// Decodes the wire layout without validating its contents.
    fn from(value: [u8; SIGNATURE_NOISE_MESSAGE_SIZE]) -> Self {
        Self {
            version: u16::from_le_bytes(value[0..2].try_into().unwrap()),
            valid_from: u32::from_le_bytes(value[2..6].try_into().unwrap()),
            not_valid_after: u32::from_le_bytes(value[6..10].try_into().unwrap()),
            signature: value[10..].try_into().unwrap(),
        }
    }
}

impl From<Certificate> for [u8; SIGNATURE_NOISE_MESSAGE_SIZE] {
    fn from(value: Certificate) -> Self {
        value.to_bytes()
    }
}

impl Certificate {
    /// Certificate format version. Only [`CERTIFICATE_VERSION`] is supported.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Start of the validity window, as a Unix timestamp in seconds.
    pub fn valid_from(&self) -> u32 {
        self.valid_from
    }

    /// End of the validity window, as a Unix timestamp in seconds.
    pub fn not_valid_after(&self) -> u32 {
        self.not_valid_after
    }

    /// Encodes the little-endian version and timestamps followed by the Schnorr signature.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_NOISE_MESSAGE_SIZE] {
        let mut encoded = [0; SIGNATURE_NOISE_MESSAGE_SIZE];
        encoded[..10].copy_from_slice(&self.header());
        encoded[10..].copy_from_slice(&self.signature);
        encoded
    }

    /// Issues a certificate over `static_pk`, using system randomness for the Schnorr signature.
    ///
    /// Returns [`Error::InvalidCertificate`] if the validity window is reversed.
    #[cfg(feature = "std")]
    pub fn issue(
        static_pk: &XOnlyPublicKey,
        authority: &Keypair,
        valid_from: u32,
        not_valid_after: u32,
    ) -> Result<Self, Error> {
        Self::issue_with_rng(
            static_pk,
            authority,
            valid_from,
            not_valid_after,
            &mut rand::thread_rng(),
        )
    }

    /// Issues a certificate over `static_pk` with an explicit random number generator.
    ///
    /// The issuer chooses Unix timestamps in seconds. Returns [`Error::InvalidCertificate`] if
    /// `valid_from > not_valid_after`. The certificate can be issued before its validity starts.
    pub fn issue_with_rng<R: rand::Rng + rand::CryptoRng>(
        static_pk: &XOnlyPublicKey,
        authority: &Keypair,
        valid_from: u32,
        not_valid_after: u32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut certificate = Self {
            version: CERTIFICATE_VERSION,
            valid_from,
            not_valid_after,
            signature: [0; 64],
        };
        if valid_from > not_valid_after {
            return Err(Error::InvalidCertificate(certificate));
        }
        let message = certificate.signing_message(static_pk);
        certificate.signature = *Secp256k1::signing_only()
            .sign_schnorr_with_rng(&message, authority, rng)
            .as_ref();
        Ok(certificate)
    }

    /// Authenticates the certificate and its validity window at the current system time.
    #[cfg(feature = "std")]
    pub fn verify(&self, static_pk: &XOnlyPublicKey, authority_pk: &XOnlyPublicKey) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.verify_with_now(static_pk, authority_pk, now)
    }

    /// Authenticates this certificate over `static_pk` using the required authority public key.
    ///
    /// Checks the version, ordered validity window, Schnorr signature, and `now` (a Unix timestamp
    /// in seconds), allowing [`CERTIFICATE_TIME_LEEWAY`] seconds of clock drift at each edge.
    pub fn verify_with_now(
        &self,
        static_pk: &XOnlyPublicKey,
        authority_pk: &XOnlyPublicKey,
        now: u32,
    ) -> bool {
        self.valid_from.saturating_sub(CERTIFICATE_TIME_LEEWAY) <= now
            && self.not_valid_after.saturating_add(CERTIFICATE_TIME_LEEWAY) >= now
            && self.verify_signature(static_pk, authority_pk)
    }

    // Binding and format checks are independent of time so servers can stage a future certificate.
    pub(crate) fn verify_signature(
        &self,
        static_pk: &XOnlyPublicKey,
        authority_pk: &XOnlyPublicKey,
    ) -> bool {
        if self.version != CERTIFICATE_VERSION || self.valid_from > self.not_valid_after {
            return false;
        }
        let signature =
            Signature::from_slice(&self.signature).expect("a Schnorr signature is 64 bytes");
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &self.signing_message(static_pk), authority_pk)
            .is_ok()
    }

    // Unauthenticated responders still send the versioned payload required by the NX wire format.
    pub(crate) fn unauthenticated() -> Self {
        Self {
            version: CERTIFICATE_VERSION,
            valid_from: 0,
            not_valid_after: u32::MAX,
            signature: [0; 64],
        }
    }

    fn header(&self) -> [u8; 10] {
        let mut header = [0; 10];
        header[..2].copy_from_slice(&self.version.to_le_bytes());
        header[2..6].copy_from_slice(&self.valid_from.to_le_bytes());
        header[6..10].copy_from_slice(&self.not_valid_after.to_le_bytes());
        header
    }

    fn signing_message(&self, static_pk: &XOnlyPublicKey) -> Message {
        let mut payload = [0; 42];
        payload[..10].copy_from_slice(&self.header());
        payload[10..].copy_from_slice(&static_pk.serialize());
        Message::from_hashed_data::<sha256::Hash>(&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn byte_encoding_round_trips() {
        let mut encoded = [0; SIGNATURE_NOISE_MESSAGE_SIZE];
        for (index, byte) in encoded.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let certificate = Certificate::from(encoded);
        assert_eq!(certificate.version(), u16::from_le_bytes([0, 1]));
        assert_eq!(certificate.valid_from(), u32::from_le_bytes([2, 3, 4, 5]));
        assert_eq!(
            certificate.not_valid_after(),
            u32::from_le_bytes([6, 7, 8, 9])
        );
        assert_eq!(certificate.to_bytes(), encoded);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn verification_checks_clock_edges_and_saturates() {
        let mut rng = StdRng::seed_from_u64(42);
        let authority = Keypair::new(&Secp256k1::new(), &mut rng);
        let static_key = Keypair::new(&Secp256k1::new(), &mut rng);
        let pk = static_key.x_only_public_key().0;
        let authority_pk = authority.x_only_public_key().0;
        let certificate = Certificate::issue_with_rng(&pk, &authority, 100, 200, &mut rng).unwrap();
        for (now, accepted) in [
            (89, false),
            (90, true),
            (150, true),
            (210, true),
            (211, false),
        ] {
            assert_eq!(
                certificate.verify_with_now(&pk, &authority_pk, now),
                accepted
            );
        }
        let low = Certificate::issue_with_rng(&pk, &authority, 0, 0, &mut rng).unwrap();
        assert!(low.verify_with_now(&pk, &authority_pk, 0));
        assert!(!low.verify_with_now(&pk, &authority_pk, u32::MAX));
        let high =
            Certificate::issue_with_rng(&pk, &authority, u32::MAX, u32::MAX, &mut rng).unwrap();
        assert!(high.verify_with_now(&pk, &authority_pk, u32::MAX));
        assert!(!high.verify_with_now(&pk, &authority_pk, 0));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn signed_unsupported_version_and_reversed_window_are_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let authority = Keypair::new(&Secp256k1::new(), &mut rng);
        let static_key = Keypair::new(&Secp256k1::new(), &mut rng);
        let pk = static_key.x_only_public_key().0;
        let authority_pk = authority.x_only_public_key().0;
        assert!(matches!(
            Certificate::issue_with_rng(&pk, &authority, 110, 100, &mut rng),
            Err(Error::InvalidCertificate(_))
        ));
        for (version, start, end) in [
            (CERTIFICATE_VERSION + 1, 100, 200),
            (CERTIFICATE_VERSION, 110, 100),
        ] {
            let mut certificate = Certificate {
                version,
                valid_from: start,
                not_valid_after: end,
                signature: [0; 64],
            };
            certificate.signature = *Secp256k1::signing_only()
                .sign_schnorr_with_rng(&certificate.signing_message(&pk), &authority, &mut rng)
                .as_ref();
            assert!(!certificate.verify_with_now(&pk, &authority_pk, 105));
        }
    }
}
