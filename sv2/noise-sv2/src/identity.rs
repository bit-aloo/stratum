use core::time::Duration;

use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::{Certificate, Error};

/// Whether an initiator requires authority authentication of the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitiatorAuthentication {
    /// Accept any responder that completes the encrypted handshake with a supported version.
    ///
    /// This protects against passive eavesdropping, but allows an active attacker to impersonate
    /// the responder. Use only on a trusted network. The resulting transport does not record
    /// whether the responder was authenticated.
    Unauthenticated,
    /// Require a valid, current certificate signed by this authority public key.
    Authority(XOnlyPublicKey),
}

impl InitiatorAuthentication {
    /// Requires authentication by a raw, x-only authority public key.
    pub fn from_raw_k(key: [u8; 32]) -> Result<Self, Error> {
        XOnlyPublicKey::from_slice(&key)
            .map(Self::Authority)
            .map_err(|_| Error::InvalidRawPublicKey)
    }
}

/// Reusable responder credentials. Construct a fresh [`crate::Responder`] for each connection.
///
/// Production servers should use [`Self::Certified`] to keep the authority private key off the
/// server. Dropping an identity non-securely erases its keypair, as supported by `secp256k1`;
/// copies retained by the caller are unaffected.
pub enum ResponderIdentity {
    /// Generate handshake keys and send an unsigned certificate payload.
    ///
    /// Only initiators configured with [`InitiatorAuthentication::Unauthenticated`] accept it.
    Unauthenticated,
    /// Sign a fresh certificate for each handshake. Intended for development and testing:
    /// the server holds the authority private key, which can impersonate the operator even after
    /// any previously issued certificate expires.
    Authority {
        /// Authority keypair whose public key initiators pin.
        authority: Keypair,
        /// Certificate lifetime in seconds from the responder's handshake time.
        certificate_validity: u32,
    },
    /// A static key and certificate whose authority signature has been checked together.
    Certified(CertifiedStaticKey),
}

impl ResponderIdentity {
    /// Constructs an authority identity from matching raw x-only public and secret keys.
    ///
    /// Fails for an invalid secret key, mismatched public key, or a validity duration exceeding
    /// `u32::MAX` seconds. Subsecond precision is discarded.
    pub fn from_authority_kp(
        public: &[u8; 32],
        private: &[u8; 32],
        certificate_validity: Duration,
    ) -> Result<Self, Error> {
        let certificate_validity = certificate_validity
            .as_secs()
            .try_into()
            .map_err(|_| Error::InvalidCertificateValidity)?;
        let mut secret = SecretKey::from_slice(private).map_err(|_| Error::InvalidRawPrivateKey)?;
        let mut authority = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        secret.non_secure_erase();
        if authority.x_only_public_key().0.serialize() != *public {
            authority.non_secure_erase();
            return Err(Error::InvalidRawPublicKey);
        }
        Ok(Self::Authority {
            authority,
            certificate_validity,
        })
    }
}

impl core::fmt::Debug for ResponderIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("Unauthenticated"),
            Self::Authority {
                certificate_validity,
                ..
            } => f
                .debug_struct("Authority")
                .field("certificate_validity", certificate_validity)
                .finish_non_exhaustive(),
            Self::Certified(key) => f.debug_tuple("Certified").field(key).finish(),
        }
    }
}

impl Drop for ResponderIdentity {
    fn drop(&mut self) {
        if let Self::Authority { authority, .. } = self {
            authority.non_secure_erase();
        }
    }
}

/// A static key paired with a certificate signed for it by the expected authority.
///
/// Fields are private so the checked pairing cannot be changed. Time validity is checked by the
/// initiator on every handshake; construction permits expired and future certificates, allowing
/// provisioning independently of the server's clock. This value is reusable across connections.
pub struct CertifiedStaticKey {
    pub(crate) static_key: Keypair,
    pub(crate) certificate: Certificate,
}

impl CertifiedStaticKey {
    /// Checks the certificate's format, ordered validity window, and signature over `static_key`.
    ///
    /// The authority public key is needed only for this check; the authority private key is never
    /// needed. Returns [`Error::InvalidCertificate`] on failure. This does not check current time.
    pub fn new(
        mut static_key: Keypair,
        certificate: Certificate,
        authority_pk: &XOnlyPublicKey,
    ) -> Result<Self, Error> {
        if !certificate.verify_signature(&static_key.x_only_public_key().0, authority_pk) {
            static_key.non_secure_erase();
            return Err(Error::InvalidCertificate(certificate));
        }
        Ok(Self {
            static_key,
            certificate,
        })
    }

    /// The immutable certificate supplied at construction, including its renewal deadline.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
}

impl core::fmt::Debug for CertifiedStaticKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CertifiedStaticKey")
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl Drop for CertifiedStaticKey {
    fn drop(&mut self) {
        self.static_key.non_secure_erase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn raw_authority_credentials_are_checked_without_truncating_validity() {
        let mut rng = StdRng::seed_from_u64(42);
        let authority = Keypair::new(&Secp256k1::new(), &mut rng);
        let public = authority.x_only_public_key().0.serialize();
        let secret = authority.secret_key().secret_bytes();
        assert!(
            ResponderIdentity::from_authority_kp(&public, &secret, Duration::from_secs(60)).is_ok()
        );
        assert!(matches!(
            ResponderIdentity::from_authority_kp(&public, &[0; 32], Duration::from_secs(60)),
            Err(Error::InvalidRawPrivateKey)
        ));
        assert!(matches!(
            ResponderIdentity::from_authority_kp(&[0; 32], &secret, Duration::from_secs(60)),
            Err(Error::InvalidRawPublicKey)
        ));
        assert!(matches!(
            ResponderIdentity::from_authority_kp(
                &public,
                &secret,
                Duration::from_secs(u32::MAX as u64 + 1)
            ),
            Err(Error::InvalidCertificateValidity)
        ));
        assert!(matches!(
            InitiatorAuthentication::from_raw_k([0; 32]),
            Err(Error::InvalidRawPublicKey)
        ));
    }
}
