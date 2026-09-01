//! # Stratum V2 Codec Library
//!
//! `codec_sv2` provides the message encoding and decoding functionality for the Stratum V2 (Sv2)
//! protocol, handling secure communication between Sv2 roles.
//!
//! This crate abstracts the complexity of message encoding/decoding with optional Noise protocol
//! support, ensuring both regular and encrypted messages can be serialized, transmitted, and
//! decoded consistently and reliably.
//!
//!
//! ## Usage
//! `codec-sv2` supports both standard Sv2 frames (unencrypted) and, under the `noise_sv2`
//! feature, Noise-encrypted Sv2 frames. To encode messages for transmission use the [`Encoder`]
//! or the `NoiseEncoder`, and to decode received messages use the [`StandardDecoder`] or the
//! `StandardNoiseDecoder`.
//!
//! A Noise connection has two phases, and the `state` module gives each its own type, so the
//! codec method that fits the phase is the only one available: a `Handshake` encodes and decodes
//! through `NoiseEncoder::encode_handshake` and `StandardNoiseDecoder::next_handshake_frame`, and
//! the `Transport` it completes into splits into the halves `NoiseEncoder::encode_transport` and
//! `StandardNoiseDecoder::next_transport_frame` take.
//!
//! ## Build Options
//!
//! This crate can be built with the following features:
//!
//! - `std`: Enable usage of rust `std` library, enabled by default.
//! - `noise_sv2`: Enables support for Noise protocol encryption and decryption.
//! - `with_buffer_pool`: Enables buffer pooling for more efficient memory management.
//!
//! In order to use this crate in a `#![no_std]` environment, use the `--no-default-features` to
//! remove the `std` feature.
//!
//! ## Examples
//!
//! See the examples for more information:
//!
//! - [Unencrypted Example](https://github.com/stratum-mining/stratum/blob/main/protocols/v2/codec-sv2/examples/unencrypted.rs)
//! - [Encrypted Example](https://github.com/stratum-mining/stratum/blob/main/protocols/v2/codec-sv2/examples/encrypted.rs)

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use buffer_sv2::Buffer as IsBuffer;
#[cfg(feature = "noise_sv2")]
use framing_sv2::{header::Header, SV2_FRAME_CHUNK_SIZE, SV2_FRAME_HEADER_SIZE};
#[cfg(feature = "noise_sv2")]
use noise_sv2::AEAD_MAC_LEN;

pub mod decoder;
pub mod encoder;
pub mod error;
#[cfg(feature = "noise_sv2")]
pub mod state;

pub use error::{Error, Result};

// The currency the encoders and decoders deal in, re-exported so that a caller only needs this
// crate in scope. EncodableFrame has to be, since the encoders take it as a bound.
pub use framing_sv2::framing::{EncodableFrame, SerializedSv2Frame, Sv2Frame};

pub use decoder::StandardDecoder;
#[cfg(feature = "noise_sv2")]
pub use decoder::StandardNoiseDecoder;

pub use encoder::Encoder;
#[cfg(feature = "noise_sv2")]
pub use encoder::NoiseEncoder;

#[cfg(feature = "noise_sv2")]
pub use state::{
    Handshake, HandshakeRole, Transport, TransportDecryptState, TransportEncryptState,
};

// The buffer type backing the encoders and decoders: pool-allocated with `with_buffer_pool`, a
// plain system memory buffer otherwise.
#[cfg(not(feature = "with_buffer_pool"))]
pub(crate) type Buffer = buffer_sv2::BufferFromSystemMemory;

#[cfg(feature = "with_buffer_pool")]
pub(crate) type Buffer = buffer_sv2::BufferPool<buffer_sv2::BufferFromSystemMemory>;

/// Size of an encrypted Sv2 frame header, including the MAC that seals it.
#[cfg(feature = "noise_sv2")]
pub const ENCRYPTED_SV2_FRAME_HEADER_SIZE: usize = SV2_FRAME_HEADER_SIZE + AEAD_MAC_LEN;

/// Length the payload `header` declares takes once encrypted, including the MAC of every chunk.
///
/// A payload longer than [`framing_sv2::SV2_FRAME_CHUNK_SIZE`] is encrypted in chunks, and each
/// chunk is sealed with its own MAC.
#[cfg(feature = "noise_sv2")]
pub fn encrypted_payload_length(header: &Header) -> usize {
    let len = header.payload_length();
    let chunks = len.div_ceil(SV2_FRAME_CHUNK_SIZE - AEAD_MAC_LEN);
    len + chunks * AEAD_MAC_LEN
}

// Default buffer sizes, without and with a buffer pool.
pub(crate) const DEFAULT_BUFFER_SIZE: usize = 512;
pub(crate) const DEFAULT_POOL_BUFFER_SIZE: usize = 2_usize.pow(16) * 5;

/// An Sv2 frame as the decoders hand it back, carrying the bytes read off the wire.
pub type StandardSerializedFrame = SerializedSv2Frame<<Buffer as IsBuffer>::Slice>;

#[cfg(test)]
#[cfg(feature = "noise_sv2")]
mod tests {
    use crate::{
        Error, Handshake, NoiseEncoder, StandardNoiseDecoder, TransportDecryptState,
        TransportEncryptState,
    };
    use binary_sv2::{Deserialize, Serialize, B064K};
    use framing_sv2::header::Header;
    use framing_sv2::{framing::Sv2Frame, SV2_FRAME_CHUNK_SIZE, SV2_FRAME_HEADER_SIZE};
    use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
    use noise_sv2::{
        Initiator, Responder, AEAD_MAC_LEN, ELLSWIFT_ENCODING_SIZE,
        INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE,
    };
    use quickcheck::Arbitrary;
    use quickcheck_macros::quickcheck;

    const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const AUTHORITY_PRIVATE_K: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
    const CERT_VALIDITY: core::time::Duration = core::time::Duration::from_secs(3600);
    const MSG_TYPE: u8 = 0xff;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestMsg {
        nonce: u16,
    }

    // A message whose payload can be made large enough to span more than one chunk.
    #[derive(Debug, Serialize, Deserialize)]
    struct ChunkedMsg<'decoder> {
        data: B064K<'decoder>,
    }

    fn round_trip(
        encoder: &mut NoiseEncoder,
        decoder: &mut StandardNoiseDecoder,
        enc: &mut TransportEncryptState,
        dec: &mut TransportDecryptState,
        nonce: u16,
    ) -> u16 {
        let frame = Sv2Frame::from_message(TestMsg { nonce }, MSG_TYPE, 0, false).unwrap();
        let encrypted = encoder.encode_transport(frame, enc).unwrap();

        let mut offset = 0;
        loop {
            let writable = decoder.writable();
            let len = writable.len();
            writable.copy_from_slice(&encrypted[offset..offset + len]);
            offset += len;

            match decoder.next_transport_frame(dec) {
                Ok(mut frame) => {
                    assert_eq!(frame.header().msg_type(), MSG_TYPE);
                    let msg: TestMsg = binary_sv2::from_bytes(frame.payload()).unwrap();
                    return msg.nonce;
                }
                Err(Error::MissingBytes(_)) => {}
                Err(e) => panic!("failed to decode a transport frame: {e:?}"),
            }
        }
    }

    fn transport_halves() -> (
        TransportEncryptState,
        TransportDecryptState,
        TransportEncryptState,
        TransportDecryptState,
    ) {
        let authority_public_k: Secp256k1PublicKey =
            AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();
        let authority_private_k: Secp256k1SecretKey =
            AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();

        let mut initiator =
            Handshake::new(Initiator::from_raw_k(authority_public_k.into_bytes()).unwrap());
        let responder = Handshake::new(
            Responder::from_authority_kp(
                &authority_public_k.into_bytes(),
                &authority_private_k.into_bytes(),
                CERT_VALIDITY,
            )
            .unwrap(),
        );

        let first_message: [u8; ELLSWIFT_ENCODING_SIZE] =
            initiator.step_0().unwrap().payload().try_into().unwrap();
        let (second_message, responder_transport) = responder.step_1(first_message).unwrap();
        let second_message: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
            second_message.payload().try_into().unwrap();
        let initiator_transport = initiator.step_2(second_message).unwrap();

        let (initiator_enc, initiator_dec) = initiator_transport.split();
        let (responder_enc, responder_dec) = responder_transport.split();
        (initiator_enc, initiator_dec, responder_enc, responder_dec)
    }

    #[test]
    fn split_transport_round_trips_in_both_directions() {
        let (mut initiator_enc, mut initiator_dec, mut responder_enc, mut responder_dec) =
            transport_halves();
        let mut encoder = NoiseEncoder::new();

        // One decoder per direction, kept for every frame, as a connection would: leftover buffer
        // state carries from one frame to the next here.
        let mut to_responder = StandardNoiseDecoder::new();
        let mut to_initiator = StandardNoiseDecoder::new();

        // Each half keeps its own cipher and nonce counter, so the two sides only stay in step
        // across repeated frames if every frame is sealed and opened by the matching direction.
        for nonce in 0..8u16 {
            assert_eq!(
                round_trip(
                    &mut encoder,
                    &mut to_responder,
                    &mut initiator_enc,
                    &mut responder_dec,
                    nonce
                ),
                nonce
            );
            assert_eq!(
                round_trip(
                    &mut encoder,
                    &mut to_initiator,
                    &mut responder_enc,
                    &mut initiator_dec,
                    nonce + 100
                ),
                nonce + 100
            );
        }
    }

    #[test]
    fn split_transport_round_trips_a_frame_that_spans_several_chunks() {
        let (mut initiator_enc, _, _, mut responder_dec) = transport_halves();

        // The encoder seals, and the decoder opens, at most `SV2_FRAME_CHUNK_SIZE - AEAD_MAC_LEN`
        // bytes of frame at a time, so a payload past that boundary is what makes both of them
        // loop. Anything smaller only ever exercises the single-chunk path.
        let mut data = vec![0xab; u16::MAX as usize];
        assert!(data.len() > SV2_FRAME_CHUNK_SIZE - AEAD_MAC_LEN);
        let msg = ChunkedMsg {
            data: (&mut data[..]).try_into().unwrap(),
        };

        let frame = Sv2Frame::from_message(msg, MSG_TYPE, 0, false).unwrap();
        let mut encoder = NoiseEncoder::new();
        let encrypted = encoder.encode_transport(frame, &mut initiator_enc).unwrap();

        let mut decoder = StandardNoiseDecoder::new();
        let mut offset = 0;
        loop {
            let writable = decoder.writable();
            let len = writable.len();
            writable.copy_from_slice(&encrypted[offset..offset + len]);
            offset += len;

            match decoder.next_transport_frame(&mut responder_dec) {
                Ok(mut frame) => {
                    assert_eq!(frame.header().msg_type(), MSG_TYPE);
                    let decoded: ChunkedMsg = binary_sv2::from_bytes(frame.payload()).unwrap();
                    assert_eq!(decoded.data.as_bytes(), &vec![0xab; u16::MAX as usize][..]);
                    break;
                }
                Err(Error::MissingBytes(_)) => {}
                Err(e) => panic!("failed to decode a chunked transport frame: {e:?}"),
            }
        }
    }

    /// The handshake runs through the codec itself, rather than around it: every message is
    /// written by `encode_handshake` and read back by `next_handshake_frame`, and the transport
    /// keys the two sides derive agree.
    #[test]
    fn a_handshake_round_trips_through_the_codec() {
        let authority_public_k: Secp256k1PublicKey =
            AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();
        let authority_private_k: Secp256k1SecretKey =
            AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();

        let mut initiator =
            Handshake::new(Initiator::from_raw_k(authority_public_k.into_bytes()).unwrap());
        let responder = Handshake::new(
            Responder::from_authority_kp(
                &authority_public_k.into_bytes(),
                &authority_private_k.into_bytes(),
                CERT_VALIDITY,
            )
            .unwrap(),
        );

        let mut encoder = NoiseEncoder::new();
        let mut to_responder = StandardNoiseDecoder::new();
        let mut to_initiator = StandardNoiseDecoder::new();

        let first = encoder
            .encode_handshake(initiator.step_0().unwrap())
            .unwrap();
        assert_eq!(first.as_ref().len(), ELLSWIFT_ENCODING_SIZE);
        let first = read_handshake_frame(&mut to_responder, &responder, first.as_ref());
        let first: [u8; ELLSWIFT_ENCODING_SIZE] = first.payload().try_into().unwrap();

        let (second, responder_transport) = responder.step_1(first).unwrap();
        let second = encoder.encode_handshake(second).unwrap();
        assert_eq!(
            second.as_ref().len(),
            INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE
        );
        let second = read_handshake_frame(&mut to_initiator, &initiator, second.as_ref());
        let second: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
            second.payload().try_into().unwrap();

        let initiator_transport = initiator.step_2(second).unwrap();

        let (mut initiator_enc, _) = initiator_transport.split();
        let (_, mut responder_dec) = responder_transport.split();
        assert_eq!(
            round_trip(
                &mut encoder,
                &mut StandardNoiseDecoder::new(),
                &mut initiator_enc,
                &mut responder_dec,
                7
            ),
            7
        );
    }

    fn read_handshake_frame<R: crate::HandshakeRole>(
        decoder: &mut StandardNoiseDecoder,
        state: &Handshake<R>,
        encoded: &[u8],
    ) -> framing_sv2::framing::HandshakeFrame {
        let mut offset = 0;
        loop {
            let writable = decoder.writable();
            let len = writable.len();
            writable.copy_from_slice(&encoded[offset..offset + len]);
            offset += len;

            match decoder.next_handshake_frame(state) {
                Ok(frame) => return frame,
                Err(Error::MissingBytes(_)) => {}
                Err(e) => panic!("failed to decode a handshake frame: {e:?}"),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ValidU24(u32);

    impl Arbitrary for ValidU24 {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            ValidU24(u32::arbitrary(g) % 16_777_216)
        }
    }

    /// Every chunk the payload is split into is sealed with its own MAC, so the encrypted length
    /// grows by one MAC per chunk and not by one MAC overall.
    #[quickcheck]
    fn prop_encrypted_payload_length_counts_one_mac_per_chunk(payload_length: ValidU24) {
        let mut bytes = [0u8; SV2_FRAME_HEADER_SIZE];
        bytes[2] = 0x01;
        bytes[3..].copy_from_slice(&payload_length.0.to_le_bytes()[..3]);
        let header = Header::from_bytes(&bytes).unwrap();

        let payload_per_chunk = SV2_FRAME_CHUNK_SIZE - AEAD_MAC_LEN;
        let chunks = (payload_length.0 as usize).div_ceil(payload_per_chunk);

        assert_eq!(
            crate::encrypted_payload_length(&header),
            payload_length.0 as usize + chunks * AEAD_MAC_LEN,
            "mismatch for a {}-byte payload spanning {chunks} chunks",
            payload_length.0
        );
    }
}
