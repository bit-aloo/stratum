//! # Noise Handshake State
//!
//! One type per phase of the Noise protocol, so that the transitions between them are checked at
//! compile time:
//!
//! ```text
//! Handshake<Initiator> --step_0()-------> HandshakeFrame
//!                      --step_2(msg)----> Transport
//! Handshake<Responder> --step_1(re_pub)-> (HandshakeFrame, Transport)
//! Transport            --split()--------> (TransportEncryptState, TransportDecryptState)
//! ```
//!
//! Each role only has the steps it may take, and the step that ends the handshake consumes it.

use crate::Result;
use alloc::boxed::Box;
use buffer_sv2::AeadBuffer;
use framing_sv2::framing::HandshakeFrame;
use noise_sv2::{
    Initiator, NoiseDecryptor, NoiseEncryptor, NoiseEngine, Responder, ELLSWIFT_ENCODING_SIZE,
    INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE,
};

mod sealed {
    pub trait Sealed {}
    impl Sealed for noise_sv2::Initiator {}
    impl Sealed for noise_sv2::Responder {}
}

/// The role a [`Handshake`] plays, either [`Initiator`] (starts the handshake) or [`Responder`]
/// (answers it). Sealed: those two are the only roles.
pub trait HandshakeRole: sealed::Sealed {
    /// Size of the handshake message this role receives from its counterpart.
    const EXPECTED_MESSAGE_SIZE: usize;
}

impl HandshakeRole for Initiator {
    const EXPECTED_MESSAGE_SIZE: usize = INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE;
}

impl HandshakeRole for Responder {
    const EXPECTED_MESSAGE_SIZE: usize = ELLSWIFT_ENCODING_SIZE;
}

/// The codec state while the handshake runs, in the role `R`. Frames exchanged in this state are
/// not encrypted yet.
///
/// A step belonging to the other role does not exist:
///
/// ```compile_fail
/// use codec_sv2::Handshake;
/// use noise_sv2::Responder;
///
/// fn responder() -> Handshake<Responder> { unimplemented!() }
///
/// responder().step_0().unwrap();
/// ```
///
/// Neither does replaying a handshake that is over:
///
/// ```compile_fail
/// use codec_sv2::Handshake;
/// use noise_sv2::{Responder, ELLSWIFT_ENCODING_SIZE};
///
/// fn responder() -> Handshake<Responder> { unimplemented!() }
///
/// let responder = responder();
/// let (_first, _transport) = responder.step_1([0; ELLSWIFT_ENCODING_SIZE]).unwrap();
/// let _second = responder.step_1([0; ELLSWIFT_ENCODING_SIZE]);
/// ```
#[derive(Debug)]
pub struct Handshake<R: HandshakeRole> {
    role: Box<R>,
}

impl<R: HandshakeRole> Handshake<R> {
    /// Starts a handshake in the role `R`.
    pub fn new(role: Box<R>) -> Self {
        Self { role }
    }

    /// Size of the handshake message this role receives from its counterpart.
    pub fn expected_message_size(&self) -> usize {
        R::EXPECTED_MESSAGE_SIZE
    }
}

impl Handshake<Initiator> {
    /// Creates the initial handshake message.
    ///
    /// The initiator stays in this state until [`Handshake::step_2`] is called with the
    /// responder's reply.
    pub fn step_0(&mut self) -> Result<HandshakeFrame> {
        self.role
            .step_0()
            .map_err(Into::into)
            .map(HandshakeFrame::from_message)
    }

    /// Completes the handshake with the responder's reply, consuming the state.
    #[cfg(feature = "std")]
    pub fn step_2(
        self,
        message: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE],
    ) -> Result<Transport> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.step_2_with_now(message, now)
    }

    /// [`Self::step_2`] given the current system time, for `no_std` environments that have
    /// another source of time.
    #[inline]
    pub fn step_2_with_now(
        mut self,
        message: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE],
        now: u32,
    ) -> Result<Transport> {
        self.role
            .step_2_with_now(message, now)
            .map_err(Into::into)
            .map(Transport::new)
    }
}

impl Handshake<Responder> {
    /// Answers the initiator's public key, completing the handshake on this side and consuming
    /// the state. The returned frame is what the initiator needs for its [`Handshake::step_2`].
    #[cfg(feature = "std")]
    pub fn step_1(
        self,
        re_pub: [u8; ELLSWIFT_ENCODING_SIZE],
    ) -> Result<(HandshakeFrame, Transport)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        self.step_1_with_now_rng(re_pub, now, &mut rand::thread_rng())
    }

    /// [`Self::step_1`] given the current time and a random number generator, for `no_std`
    /// environments that have their own of each.
    #[inline]
    pub fn step_1_with_now_rng<G: rand::Rng + rand::CryptoRng>(
        mut self,
        re_pub: [u8; ELLSWIFT_ENCODING_SIZE],
        now: u32,
        rng: &mut G,
    ) -> Result<(HandshakeFrame, Transport)> {
        let (message, engine) = self.role.step_1_with_now_rng(re_pub, now, rng)?;
        Ok((
            HandshakeFrame::from_message(message),
            Transport::new(engine),
        ))
    }
}

/// The codec state once the handshake is complete, where AEAD encryption and decryption are
/// operational.
///
/// Completing a [`Handshake`] is the only way to build one, which is what makes
/// [`Transport::split`] infallible:
///
/// ```compile_fail
/// use codec_sv2::Transport;
/// use noise_sv2::NoiseEngine;
///
/// fn engine() -> NoiseEngine { unimplemented!() }
///
/// let transport = Transport { engine: engine() };
/// ```
#[derive(Debug)]
pub struct Transport {
    engine: NoiseEngine,
}

impl Transport {
    fn new(engine: NoiseEngine) -> Self {
        Self { engine }
    }

    /// Splits into the half the encoder uses and the half the decoder uses, consuming it.
    pub fn split(self) -> (TransportEncryptState, TransportDecryptState) {
        let (encryption, decryption) = self.engine.into_split();
        (
            TransportEncryptState { encryption },
            TransportDecryptState { decryption },
        )
    }
}

/// The encrypting half of a [`Transport`].
#[derive(Debug)]
pub struct TransportEncryptState {
    encryption: NoiseEncryptor,
}

impl TransportEncryptState {
    pub(crate) fn encrypt<T: AeadBuffer>(&mut self, msg: &mut T) -> Result<()> {
        self.encryption.encrypt(msg).map_err(Into::into)
    }
}

/// The decrypting half of a [`Transport`].
#[derive(Debug)]
pub struct TransportDecryptState {
    decryption: NoiseDecryptor,
}

impl TransportDecryptState {
    pub(crate) fn decrypt<T: AeadBuffer>(&mut self, msg: &mut T) -> Result<()> {
        self.decryption.decrypt(msg).map_err(Into::into)
    }
}
