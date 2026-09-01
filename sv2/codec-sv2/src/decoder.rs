//! # Decoder
//!
//! Provides utilities for decoding messages held by Sv2 frames, with or without Noise protocol
//! support.
//!
//! It includes primitives to both decode encoded standard Sv2 frames and to decrypt and decode
//! Noise-encrypted encoded Sv2 frames, ensuring secure communication when required.
//!
//! ## Usage
//! All messages passed between Sv2 roles are encoded as Sv2 frames. These frames are decoded using
//! primitives in this module. There are two types of decoders for reading these frames: one for
//! regular Sv2 frames [`StandardDecoder`], and another for Noise-encrypted frames
//! `StandardNoiseDecoder` (under the `noise_sv2` feature). Both decoders manage the
//! deserialization of incoming data and, when applicable, the decryption of the data upon
//! receiving the transmitted message.
//!
//! ### Buffer Management
//!
//! The decoders rely on buffers to hold intermediate data during the decoding process.
//!
//! - When the `with_buffer_pool` feature is enabled, the internal `Buffer` type is backed by a
//!   pool-allocated buffer [`buffer_sv2::BufferPool`], providing more efficient memory usage,
//!   particularly in high-throughput scenarios.
//! - If this feature is not enabled, a system memory buffer [`buffer_sv2::BufferFromSystemMemory`]
//!   is used for simpler applications where memory efficiency is less critical.

#[cfg(feature = "noise_sv2")]
use buffer_sv2::AeadBuffer;
use buffer_sv2::Buffer as IsBuffer;
#[cfg(feature = "noise_sv2")]
use framing_sv2::{framing::HandshakeFrame, SV2_FRAME_HEADER_SIZE};
use framing_sv2::{
    framing::{SerializedSv2Frame, SizeHint},
    header::Header,
    SV2_FRAME_CHUNK_SIZE,
};
#[cfg(feature = "noise_sv2")]
use noise_sv2::NOISE_FRAME_HEADER_SIZE;

use crate::{
    error::{Error, Result},
    Buffer,
    Error::MissingBytes,
};
#[cfg(feature = "noise_sv2")]
use crate::{
    state::{Handshake, HandshakeRole},
    TransportDecryptState, ENCRYPTED_SV2_FRAME_HEADER_SIZE,
};

/// Standard Sv2 decoder with Noise protocol support.
///
/// Used for decoding Sv2 frames encrypted via the Noise protocol.
#[cfg(feature = "noise_sv2")]
pub type StandardNoiseDecoder = WithNoise<Buffer>;

/// Standard Sv2 decoder without Noise protocol support.
///
/// Used for decoding plain Sv2 frames.
pub type StandardDecoder = WithoutNoise<Buffer>;

/// Decoder for Sv2 frames with Noise protocol support.
///
/// Accumulates the encrypted data into a dedicated buffer until the entire encrypted frame is
/// received. The Noise protocol is then used to decrypt the accumulated data into another
/// dedicated buffer, converting it back into its original serialized form. This decrypted data is
/// then deserialized into the original Sv2 frame and message format.
#[cfg(feature = "noise_sv2")]
#[derive(Debug)]
pub struct WithNoise<B: IsBuffer> {
    // Buffer for holding incoming encrypted Noise data to be decrypted.
    //
    // Stores the incoming encrypted data, allowing the decoder to accumulate the necessary bytes
    // for full decryption. Once the entire encrypted frame is received, the decoder processes the
    // buffer to extract the underlying frame.
    noise_buffer: B,

    // Buffer for holding decrypted data to be decoded.
    //
    // Stores the decrypted data until it is ready to be processed and converted into a Sv2 frame.
    sv2_buffer: B,

    // Tracks the number of bytes remaining until the full frame is received.
    //
    // Ensures that the full encrypted Noise frame has been received by keeping track of the
    // remaining bytes. Once the complete frame is received, decoding can proceed.
    missing_noise_b: usize,
}

#[cfg(feature = "noise_sv2")]
impl<B: IsBuffer + AeadBuffer> WithNoise<B> {
    /// Attempts to decode the next handshake frame.
    ///
    /// Handshake messages have a fixed size that depends on the role `state` plays, so no header
    /// is read: the decoder buffers exactly that many bytes.
    ///
    /// On `Error::MissingBytes`, resize the decoder buffer using `writable`, read another chunk
    /// from the stream, and call this method again until it returns `Ok`. The count it carries is
    /// what the decoder will accept on the next read, which is always [`Self::writable_len`] and
    /// never more than one chunk, not the number of bytes left in the message.
    ///
    /// `Error::UnexpectedTrailingBytes` reports bytes buffered past the end of the handshake
    /// message. The buffers are drained, so the caller must start the handshake again.
    #[inline]
    pub fn next_handshake_frame<R: HandshakeRole>(
        &mut self,
        state: &Handshake<R>,
    ) -> Result<HandshakeFrame> {
        let expected = state.expected_message_size();
        let buffered = self.noise_buffer.as_ref().len();
        if buffered > expected {
            return Err(self.reset_after_surplus(buffered - expected, expected));
        }
        match expected - buffered {
            0 => {
                self.missing_noise_b = NOISE_FRAME_HEADER_SIZE;
                Ok(self.while_handshaking())
            }
            hint => {
                self.missing_noise_b = hint;
                Err(Error::MissingBytes(self.writable_len()))
            }
        }
    }

    /// Attempts to decode the next encrypted frame with the decrypting half of a completed
    /// handshake, erroring out on a badly formatted header or a decryption failure.
    ///
    /// On `Error::MissingBytes`, resize the decoder buffer using `writable`, read another chunk
    /// from the stream, and call this method again until it returns `Ok`. The count it carries is
    /// what the decoder will accept on the next read, which is always [`Self::writable_len`] and
    /// never more than one chunk, not the number of bytes left in the frame.
    ///
    /// `Error::UnexpectedTrailingBytes` reports bytes buffered past the end of the frame. The
    /// buffers are drained, but the AEAD nonce may already have advanced for the dropped frame,
    /// so the caller must tear down the connection and re-handshake.
    #[inline]
    pub fn next_transport_frame(
        &mut self,
        state: &mut TransportDecryptState,
    ) -> Result<SerializedSv2Frame<B::Slice>> {
        self.next_transport(|buf| state.decrypt(buf))
    }

    // Decodes a transport-mode frame, decrypting through `decrypt`.
    #[inline]
    fn next_transport(
        &mut self,
        decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<SerializedSv2Frame<B::Slice>> {
        let hint = if IsBuffer::len(&self.sv2_buffer) < SV2_FRAME_HEADER_SIZE {
            let buffered = IsBuffer::len(&self.noise_buffer);
            if buffered > ENCRYPTED_SV2_FRAME_HEADER_SIZE {
                return Err(self.reset_after_surplus(
                    buffered - ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                    ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                ));
            }
            ENCRYPTED_SV2_FRAME_HEADER_SIZE - buffered
        } else {
            let src = self.sv2_buffer.get_data_by_ref(SV2_FRAME_HEADER_SIZE);
            let header = Header::from_bytes(src)?;
            let encrypted_len = crate::encrypted_payload_length(&header);
            let buffered = IsBuffer::len(&self.noise_buffer);
            if buffered > encrypted_len {
                return Err(self.reset_after_surplus(
                    buffered - encrypted_len,
                    ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                ));
            }
            encrypted_len - buffered
        };

        match hint {
            0 => {
                self.missing_noise_b = ENCRYPTED_SV2_FRAME_HEADER_SIZE;
                self.decode_noise_frame(decrypt)
            }
            _ => {
                self.missing_noise_b = hint;
                Err(Error::MissingBytes(self.writable_len()))
            }
        }
    }

    fn reset_after_surplus(&mut self, surplus: usize, missing: usize) -> Error {
        let _ = self.noise_buffer.get_data_owned();
        if !IsBuffer::is_empty(&self.sv2_buffer) {
            let _ = self.sv2_buffer.get_data_owned();
        }
        self.missing_noise_b = missing;
        Error::UnexpectedTrailingBytes(surplus)
    }

    /// Returns the number of bytes to read next for the current Noise-encrypted frame.
    ///
    /// This is how many bytes are still missing from the frame, capped at one chunk
    /// ([`framing_sv2::SV2_FRAME_CHUNK_SIZE`]), which is the unit the payload is encrypted in. A
    /// peer declares the payload length in a header it sends before any of that payload, so
    /// buffering the whole declared length up front would let it reserve megabytes with a
    /// 22-byte write; the frame is instead read a chunk at a time, and the buffer grows with the
    /// data that actually arrives.
    ///
    /// The returned length dynamically updates as data is received and processed.
    pub fn writable_len(&self) -> usize {
        self.missing_noise_b.min(SV2_FRAME_CHUNK_SIZE)
    }

    /// Provides a writable buffer for receiving incoming Noise-encrypted Sv2 data.
    ///
    /// This buffer is used to store incoming data, and its size is [`Self::writable_len`]. As new
    /// data is read, it is written into this buffer until enough data has been received to fully
    /// decode a frame. The buffer must have the correct number of bytes available to progress to
    /// the decoding process.
    #[inline]
    pub fn writable(&mut self) -> &mut [u8] {
        let writable_len = self.writable_len();
        self.noise_buffer.get_writable(writable_len)
    }

    /// Determines whether the decoder's internal buffers can be safely dropped.
    ///
    /// For more information, refer to the [`buffer_sv2`
    /// crate](https://docs.rs/buffer_sv2/latest/buffer_sv2/).
    pub fn droppable(&self) -> bool {
        self.noise_buffer.is_droppable() && self.sv2_buffer.is_droppable()
    }

    // Takes the buffered handshake message out of the `noise_buffer` as a `HandshakeFrame`.
    fn while_handshaking(&mut self) -> HandshakeFrame {
        let src = self.noise_buffer.get_data_owned().as_mut().to_vec();

        // Since the frame length is already validated during the handshake process, this
        // operation is infallible.
        // Conditionally call `.into()` based on `with_buffer_pool` feature to handle differences
        // between Clippy and test builds. See: https://github.com/stratum-mining/stratum/pull/1860#discussion_r2457908851
        #[cfg(feature = "with_buffer_pool")]
        let frame = HandshakeFrame::from_bytes(src.into());

        #[cfg(not(feature = "with_buffer_pool"))]
        let frame = HandshakeFrame::from_bytes(src);

        frame
    }

    // Decodes a Noise-encrypted Sv2 frame, handling both the message header and payload
    // decryption.
    //
    // Processes Noise-encrypted Sv2 frames by first decrypting the header, followed by the
    // payload. If the frame's data is received in chunks, it ensures that decryption occurs
    // incrementally as more encrypted data becomes available. The decrypted data is then stored in
    // the `sv2_buffer`, from which the resulting Sv2 frame is extracted and returned.
    //
    // On success, the decoded frame is returned. Otherwise, an error indicating the number of
    // missing bytes required to complete the encoded frame, an error on a badly formatted message
    // header, or a decryption failure error is returned. If there are still bytes missing to
    // complete the frame, the function will return an `Error::MissingBytes` with the number of
    // additional bytes required to fully decrypt the frame. Once all bytes are available, the
    // decryption process completes and the frame can be successfully decoded.
    #[inline]
    fn decode_noise_frame(
        &mut self,
        decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<SerializedSv2Frame<B::Slice>> {
        let result = self.try_decode_noise_frame(decrypt);

        match &result {
            // `MissingBytes` is the normal way out of the header round, so the buffer has to be
            // left exactly as it is.
            Err(Error::MissingBytes(_)) | Ok(_) => {}
            Err(_) => {
                // Not a no-op: the decrypt offset and the plaintext decrypted so far persist across
                // calls, so without this the next frame is decrypted at the failing chunk's offset.
                self.sv2_buffer.danger_set_start(0);
                self.sv2_buffer.get_data_owned();
            }
        }

        result
    }

    #[inline]
    fn try_decode_noise_frame(
        &mut self,
        mut decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<SerializedSv2Frame<B::Slice>> {
        match (
            IsBuffer::len(&self.noise_buffer),
            IsBuffer::len(&self.sv2_buffer),
        ) {
            // HERE THE SV2 HEADER IS READY TO BE DECRYPTED
            (ENCRYPTED_SV2_FRAME_HEADER_SIZE, 0) => {
                let src = self.noise_buffer.get_data_owned();
                let decrypted_header = self
                    .sv2_buffer
                    .get_writable(ENCRYPTED_SV2_FRAME_HEADER_SIZE);
                decrypted_header.copy_from_slice(src.as_ref());
                self.sv2_buffer.as_ref();
                decrypt(&mut self.sv2_buffer)?;
                let header =
                    Header::from_bytes(self.sv2_buffer.get_data_by_ref(SV2_FRAME_HEADER_SIZE))?;
                self.missing_noise_b = crate::encrypted_payload_length(&header);
                Err(Error::MissingBytes(self.writable_len()))
            }
            // HERE THE SV2 PAYLOAD IS READY TO BE DECRYPTED
            _ => {
                // DECRYPT THE PAYLOAD IN CHUNKS
                let encrypted_payload = self.noise_buffer.get_data_owned();
                let encrypted_payload_len = encrypted_payload.as_ref().len();
                let mut start = 0;
                let mut end = if encrypted_payload_len < SV2_FRAME_CHUNK_SIZE {
                    encrypted_payload_len
                } else {
                    SV2_FRAME_CHUNK_SIZE
                };
                // Do not try to decrypt the header cause it is already decrypted
                let mut decrypted_len = SV2_FRAME_HEADER_SIZE;

                while start < encrypted_payload_len {
                    let decrypted_payload = self.sv2_buffer.get_writable(end - start);
                    decrypted_payload.copy_from_slice(&encrypted_payload.as_ref()[start..end]);
                    self.sv2_buffer.danger_set_start(decrypted_len);
                    decrypt(&mut self.sv2_buffer)?;
                    start = end;
                    end = (start + SV2_FRAME_CHUNK_SIZE).min(encrypted_payload_len);
                    decrypted_len += self.sv2_buffer.as_ref().len();
                }
                self.sv2_buffer.danger_set_start(0);
                let src = self.sv2_buffer.get_data_owned();
                Ok(SerializedSv2Frame::<B::Slice>::from_bytes_unchecked(src)?)
            }
        }
    }
}

#[cfg(feature = "noise_sv2")]
impl WithNoise<Buffer> {
    /// Crates a new [`WithNoise`] decoder with default buffer sizes.
    ///
    /// Initializes the decoder with default buffer sizes and sets the number of missing bytes to
    /// 0.
    pub fn new() -> Self {
        Self {
            noise_buffer: Buffer::new(crate::DEFAULT_POOL_BUFFER_SIZE),
            sv2_buffer: Buffer::new(crate::DEFAULT_POOL_BUFFER_SIZE),
            missing_noise_b: 0,
        }
    }
}

#[cfg(feature = "noise_sv2")]
impl Default for WithNoise<Buffer> {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoder for standard Sv2 frames.
///
/// Accumulates the data into a dedicated buffer until the entire Sv2 frame is received. This data
/// is then deserialized into the original Sv2 frame and message format.
#[derive(Debug)]
pub struct WithoutNoise<B: IsBuffer> {
    // Buffer for holding incoming data to be decoded into a Sv2 frame.
    //
    // This buffer stores incoming data as it is received, allowing the decoder to accumulate the
    // necessary bytes until a full frame is available. Once the full encoded frame has been
    // received, the buffer's contents are processed and decoded into an Sv2 frame.
    buffer: B,

    // Tracks the number of bytes remaining until the full frame is received.
    //
    // Ensures that the full Sv2 frame has been received by keeping track of the remaining bytes.
    // Once the complete frame is received, decoding can proceed.
    missing_b: usize,
}

impl<B: IsBuffer> WithoutNoise<B> {
    /// Attempts to decode the next frame, returning either a frame or an error describing how the
    /// buffered bytes differ from the frame size declared by the header.
    ///
    /// `Error::MissingBytes` carries the number of bytes the decoder will accept on the next
    /// read: resize the decoder buffer using `writable`, read that many bytes from the stream,
    /// and call `next_frame` again until it returns `Ok`. The count always equals
    /// [`Self::writable_len`], so it is capped at one chunk and is not the number of bytes left
    /// in the frame — a frame longer than that takes several rounds.
    ///
    /// `Error::UnexpectedTrailingBytes` reports bytes buffered past the end of the frame. The
    /// buffer is drained — including the complete frame that preceded the surplus — so the caller
    /// must resynchronize the stream or reconnect.
    #[inline]
    pub fn next_frame(&mut self) -> Result<SerializedSv2Frame<B::Slice>> {
        let len = self.buffer.len();
        let src = self.buffer.get_data_by_ref(len);

        match SerializedSv2Frame::<B::Slice>::size_hint(src) {
            SizeHint::Exact => {
                self.missing_b = Header::SIZE;
                let src = self.buffer.get_data_owned();
                let frame = SerializedSv2Frame::<B::Slice>::from_bytes_unchecked(src)?;
                Ok(frame)
            }
            SizeHint::Missing(missing) => {
                self.missing_b = missing;
                Err(MissingBytes(self.writable_len()))
            }
            SizeHint::Surplus(surplus) => {
                self.missing_b = Header::SIZE;
                let _ = self.buffer.get_data_owned();
                Err(Error::UnexpectedTrailingBytes(surplus))
            }
        }
    }

    /// Returns the number of bytes to read next for the current frame.
    ///
    /// This is how many bytes are still missing from the frame, capped at
    /// [`framing_sv2::SV2_FRAME_CHUNK_SIZE`]. A peer declares the payload length in the header it
    /// sends before any of that payload, so buffering the whole declared length up front would
    /// let it reserve close to 16 MiB with a six-byte write; the frame is instead read a chunk at
    /// a time, and the buffer grows with the data that actually arrives.
    pub fn writable_len(&self) -> usize {
        self.missing_b.min(SV2_FRAME_CHUNK_SIZE)
    }

    /// Provides a writable buffer for receiving incoming Sv2 data.
    ///
    /// This buffer is used to store incoming data, and its size is [`Self::writable_len`]. As new
    /// data is read, it is written into this buffer until enough data has been received to fully
    /// decode a frame. The buffer must have the correct number of bytes available to progress to
    /// the decoding process.
    pub fn writable(&mut self) -> &mut [u8] {
        let writable_len = self.writable_len();
        self.buffer.get_writable(writable_len)
    }
}

impl WithoutNoise<Buffer> {
    /// Creates a new [`WithoutNoise`] with a buffer of default size.
    ///
    /// Initializes the decoder with a default buffer size and sets the number of missing bytes to
    /// the size of the header.
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(crate::DEFAULT_POOL_BUFFER_SIZE),
            missing_b: Header::SIZE,
        }
    }
}

impl Default for WithoutNoise<Buffer> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binary_sv2::{Deserialize, Serialize};
    // Not redundant: the glob import above brings in `crate::Result`, whose single type parameter
    // the code generated by the `Deserialize` derive cannot use.
    use core::result::Result;

    #[derive(Serialize, Deserialize)]
    pub struct TestMessage {}

    #[test]
    fn unencrypted_writable_with_missing_b_initialized_as_header_size() {
        let mut decoder = StandardDecoder::new();
        let actual = decoder.writable();
        let expect = [0u8; Header::SIZE];
        assert_eq!(actual, expect);
    }

    #[cfg(feature = "noise_sv2")]
    #[test]
    fn noise_handshake_frame_waits_for_the_size_the_role_expects() {
        use crate::{state::HandshakeRole, Handshake};
        use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
        use noise_sv2::Responder;

        let public_k: Secp256k1PublicKey = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
            .to_string()
            .parse()
            .unwrap();
        let private_k: Secp256k1SecretKey = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
            .to_string()
            .parse()
            .unwrap();
        let responder = Handshake::new(
            Responder::from_authority_kp(
                &public_k.into_bytes(),
                &private_k.into_bytes(),
                core::time::Duration::from_secs(3600),
            )
            .unwrap(),
        );

        let mut decoder = StandardNoiseDecoder::new();
        assert!(matches!(
            decoder.next_handshake_frame(&responder),
            Err(Error::MissingBytes(n)) if n == Responder::EXPECTED_MESSAGE_SIZE
        ));
        assert_eq!(decoder.writable_len(), Responder::EXPECTED_MESSAGE_SIZE);
    }
}

#[cfg(test)]
mod prop_tests {
    use crate::{decoder::Buffer, encoder::Encoder, StandardDecoder};
    #[cfg(feature = "noise_sv2")]
    use crate::{
        Handshake, NoiseEncoder, StandardNoiseDecoder, TransportDecryptState, TransportEncryptState,
    };
    use binary_sv2::{Deserialize, Serialize};
    use buffer_sv2::Buffer as IsBuffer;
    use framing_sv2::{
        framing::{SerializedSv2Frame, Sv2Frame},
        header::Header,
        SV2_FRAME_CHUNK_SIZE,
    };
    #[cfg(feature = "noise_sv2")]
    use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
    #[cfg(feature = "noise_sv2")]
    use noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;
    #[cfg(feature = "noise_sv2")]
    use std::convert::TryInto;
    #[cfg(feature = "noise_sv2")]
    use std::time::Duration;

    #[cfg(feature = "noise_sv2")]
    const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    #[cfg(feature = "noise_sv2")]
    const AUTHORITY_PRIVATE_K: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    type Slice = <Buffer as IsBuffer>::Slice;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    struct TestMessage {
        value: u16,
    }

    impl Arbitrary for TestMessage {
        fn arbitrary(g: &mut Gen) -> Self {
            TestMessage {
                value: u16::arbitrary(g),
            }
        }
    }

    fn decode_frame(
        decoder: &mut StandardDecoder,
        encoded_bytes: &[u8],
        chunk_size: Option<usize>,
    ) -> Option<SerializedSv2Frame<Slice>> {
        let mut offset = 0;
        while offset < encoded_bytes.len() {
            let writable = decoder.writable();
            let available = encoded_bytes.len() - offset;
            let to_copy = match chunk_size {
                Some(c) => core::cmp::min(core::cmp::min(writable.len(), c), available),
                None => core::cmp::min(writable.len(), available),
            };
            writable[..to_copy].copy_from_slice(&encoded_bytes[offset..offset + to_copy]);
            offset += to_copy;

            match decoder.next_frame() {
                Ok(frame) => return Some(frame),
                Err(crate::Error::MissingBytes(_)) => continue,
                Err(_) => return None,
            }
        }
        None
    }

    /// Verifies that encoding then decoding a frame over the standard (unencrypted) codec
    /// recovers the original message, msg_type, and ext_type exactly.
    #[quickcheck]
    fn prop_encode_decode_roundtrip(msg: TestMessage, msg_type: u8, ext_type: u16) -> TestResult {
        let original_msg = msg.clone();

        let frame = match Sv2Frame::<TestMessage>::from_message(msg, msg_type, ext_type, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let expected_ext_type = frame.header().ext_type();

        let mut encoder = Encoder::new();
        let encoded = match encoder.encode(frame) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::new();
        match decode_frame(&mut decoder, encoded.as_ref(), None) {
            Some(mut decoded_frame) => {
                let header = decoded_frame.header();
                let actual_msg_type = header.msg_type();
                let actual_ext_type = header.ext_type();
                let decoded_msg: TestMessage = match binary_sv2::from_bytes(decoded_frame.payload())
                {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                };
                TestResult::from_bool(
                    decoded_msg == original_msg
                        && actual_msg_type == msg_type
                        && actual_ext_type == expected_ext_type,
                )
            }
            None => TestResult::failed(),
        }
    }

    /// Verifies that the decoder correctly accumulates partial input, emitting `MissingBytes`
    /// on each incomplete delivery before returning the frame once all bytes arrive.
    #[quickcheck]
    fn prop_decoder_handles_partial_data(
        msg: TestMessage,
        msg_type: u8,
        chunk_size: u8,
    ) -> TestResult {
        if chunk_size == 0 {
            return TestResult::discard();
        }

        let frame = match Sv2Frame::<TestMessage>::from_message(msg, msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let mut encoder = Encoder::new();
        let encoded = match encoder.encode(frame) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::new();
        let encoded_bytes: &[u8] = encoded.as_ref();
        let chunk_size = (chunk_size as usize).max(1);

        let mut offset = 0;
        let mut missing_bytes_count = 0;
        while offset < encoded_bytes.len() {
            let writable = decoder.writable();
            let to_copy = core::cmp::min(
                core::cmp::min(writable.len(), chunk_size),
                encoded_bytes.len() - offset,
            );
            writable[..to_copy].copy_from_slice(&encoded_bytes[offset..offset + to_copy]);
            offset += to_copy;

            match decoder.next_frame() {
                Ok(_) => return TestResult::passed(),
                Err(crate::Error::MissingBytes(n)) => {
                    missing_bytes_count += 1;
                    assert!(n > 0);
                }
                Err(_) => return TestResult::failed(),
            }
        }

        TestResult::from_bool(missing_bytes_count > 0)
    }

    /// Verifies that over-filling the buffer (calling `writable` twice before `next_frame`)
    /// surfaces `UnexpectedTrailingBytes`, drains the buffer, and leaves the decoder usable.
    #[test]
    fn test_decoder_excess_bytes_drains_and_recovers() {
        let msg = TestMessage { value: 42 };
        let frame = Sv2Frame::<TestMessage>::from_message(msg.clone(), 0, 0, false).unwrap();
        let mut encoder = Encoder::new();
        let encoded = encoder.encode(frame).unwrap();
        let encoded: &[u8] = encoded.as_ref();

        let mut decoder = StandardDecoder::new();
        decoder.writable().copy_from_slice(&encoded[..Header::SIZE]);
        assert!(matches!(
            decoder.next_frame(),
            Err(crate::Error::MissingBytes(_))
        ));
        decoder.writable().copy_from_slice(&encoded[Header::SIZE..]);

        // Write past the slice `writable` returned.
        const SURPLUS: usize = 4;
        decoder
            .buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);

        match decoder.next_frame() {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            Ok(_) => panic!("expected UnexpectedTrailingBytes, got a frame"),
            Err(e) => panic!("expected UnexpectedTrailingBytes, got {e:?}"),
        }

        let mut decoded =
            decode_frame(&mut decoder, encoded, None).expect("decoder should recover");
        let decoded_msg: TestMessage = binary_sv2::from_bytes(decoded.payload()).unwrap();
        assert_eq!(decoded_msg, msg);
    }

    /// Verifies that over-filling the noise buffer (writing past the slice returned by
    /// `writable`) surfaces `UnexpectedTrailingBytes` rather than underflowing the
    /// `missing_noise_b` arithmetic, in the handshake state and in both transport phases
    /// (encrypted header pending, payload pending).
    #[cfg(feature = "noise_sv2")]
    #[test]
    fn test_noise_decoder_excess_bytes_do_not_underflow() {
        const SURPLUS: usize = 4;
        const MSG_LEN: usize = ELLSWIFT_ENCODING_SIZE;

        // Handshake state.
        let (_, responder) = make_handshake_pair();
        let mut decoder = StandardNoiseDecoder::new();
        assert!(matches!(
            decoder.next_handshake_frame(&responder),
            Err(crate::Error::MissingBytes(MSG_LEN))
        ));
        decoder.writable().fill(0);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_handshake_frame(&responder) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }
        assert_eq!(decoder.writable_len(), MSG_LEN);
        decoder.writable().fill(0);
        assert!(decoder.next_handshake_frame(&responder).is_ok());

        // Transport state, before the encrypted header has been decrypted.
        let (_, mut receiver) = make_transport_state_pair();
        let mut decoder = StandardNoiseDecoder::new();
        assert!(matches!(
            decoder.next_transport_frame(&mut receiver),
            Err(crate::Error::MissingBytes(_))
        ));
        decoder.writable().fill(0);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_transport_frame(&mut receiver) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }

        // Transport state, once the encrypted header has been decrypted.
        let (mut sender, mut receiver) = make_transport_state_pair();
        let sv2_frame =
            Sv2Frame::<TestMessage>::from_message(TestMessage { value: 42 }, 0, 0, false).unwrap();
        let mut encoder = NoiseEncoder::new();
        let encrypted = encoder.encode_transport(sv2_frame, &mut sender).unwrap();
        let encrypted: &[u8] = encrypted.as_ref();

        let mut decoder = StandardNoiseDecoder::new();
        let mut offset = 0;
        // Two rounds: prime the encrypted header size, then feed the encrypted header.
        for _ in 0..2 {
            let w = decoder.writable();
            let n = w.len().min(encrypted.len() - offset);
            w[..n].copy_from_slice(&encrypted[offset..offset + n]);
            offset += n;
            assert!(matches!(
                decoder.next_transport_frame(&mut receiver),
                Err(crate::Error::MissingBytes(_))
            ));
        }

        // The decoder now wants the payload: write it, then over-fill.
        let w = decoder.writable();
        let n = w.len().min(encrypted.len() - offset);
        w[..n].copy_from_slice(&encrypted[offset..offset + n]);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_transport_frame(&mut receiver) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }
    }

    /// A peer declares the payload length in the header it sends first, so the decoder must not
    /// size its read window from that declaration: six bytes would otherwise reserve 16 MiB.
    #[test]
    fn a_declared_frame_length_does_not_widen_the_read_window() {
        let mut decoder = StandardDecoder::new();
        decoder
            .writable()
            .copy_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff]);

        assert!(matches!(
            decoder.next_frame(),
            Err(crate::Error::MissingBytes(SV2_FRAME_CHUNK_SIZE))
        ));
        assert_eq!(decoder.writable_len(), SV2_FRAME_CHUNK_SIZE);
        assert_eq!(decoder.writable().len(), SV2_FRAME_CHUNK_SIZE);
    }

    /// A caller that sizes its read from `MissingBytes` and one that sizes it from `writable`
    /// must agree, on every round of a frame that takes more than one.
    #[test]
    fn missing_bytes_always_reports_the_next_read_window() {
        const PAYLOAD: usize = 2 * SV2_FRAME_CHUNK_SIZE + 7;

        let mut encoded = vec![0u8; Header::SIZE + PAYLOAD];
        encoded[2] = 1;
        encoded[3..Header::SIZE].copy_from_slice(&(PAYLOAD as u32).to_le_bytes()[..3]);

        let mut decoder = StandardDecoder::new();
        let mut offset = 0;
        loop {
            let missing = match decoder.next_frame() {
                Ok(_) => break,
                Err(crate::Error::MissingBytes(n)) => n,
                Err(e) => panic!("failed to decode a multi-chunk frame: {e:?}"),
            };
            let writable = decoder.writable();
            assert_eq!(missing, writable.len());
            writable[..missing].copy_from_slice(&encoded[offset..offset + missing]);
            offset += missing;
        }
        assert_eq!(offset, encoded.len());
    }

    /// The counterpart of the above: a frame longer than the read window is still decoded, over
    /// as many reads as it takes.
    #[test]
    fn a_frame_longer_than_the_read_window_is_read_over_several_rounds() {
        const PAYLOAD: usize = 3 * SV2_FRAME_CHUNK_SIZE + 7;

        let mut encoded = vec![0u8; Header::SIZE + PAYLOAD];
        encoded[2] = 1;
        encoded[3..Header::SIZE].copy_from_slice(&(PAYLOAD as u32).to_le_bytes()[..3]);
        for (i, byte) in encoded[Header::SIZE..].iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut decoder = StandardDecoder::new();
        let mut offset = 0;
        let mut rounds = 0;
        let frame = loop {
            let writable = decoder.writable();
            let n = writable.len().min(encoded.len() - offset);
            writable[..n].copy_from_slice(&encoded[offset..offset + n]);
            offset += n;
            rounds += 1;

            match decoder.next_frame() {
                Ok(frame) => break frame,
                Err(crate::Error::MissingBytes(_)) => continue,
                Err(e) => panic!("failed to decode a multi-chunk frame: {e:?}"),
            }
        };

        assert!(rounds > 2, "the frame should not fit in a single read");
        assert_eq!(frame.header().payload_length(), PAYLOAD);
        assert_eq!(frame.as_bytes(), &encoded[..]);
    }

    /// The Noise decoder learns the payload length from a header it has authenticated, but the
    /// peer still has not sent any of that payload, so the same cap applies.
    #[cfg(feature = "noise_sv2")]
    #[test]
    fn a_declared_noise_payload_length_does_not_widen_the_read_window() {
        use crate::ENCRYPTED_SV2_FRAME_HEADER_SIZE;
        use framing_sv2::SV2_FRAME_HEADER_SIZE;

        let (mut sender, mut receiver) = make_transport_state_pair();

        // Only a header, declaring the largest payload a U24 can hold.
        let mut header = Buffer::new(crate::DEFAULT_BUFFER_SIZE);
        header
            .get_writable(SV2_FRAME_HEADER_SIZE)
            .copy_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff]);
        sender.encrypt(&mut header).unwrap();
        let header = header.get_data_owned();

        let mut decoder = StandardNoiseDecoder::new();
        assert!(matches!(
            decoder.next_transport_frame(&mut receiver),
            Err(crate::Error::MissingBytes(ENCRYPTED_SV2_FRAME_HEADER_SIZE))
        ));
        decoder.writable().copy_from_slice(header.as_ref());

        assert!(matches!(
            decoder.next_transport_frame(&mut receiver),
            Err(crate::Error::MissingBytes(_))
        ));
        assert_eq!(decoder.writable_len(), SV2_FRAME_CHUNK_SIZE);
        assert_eq!(decoder.writable().len(), SV2_FRAME_CHUNK_SIZE);
    }

    /// A Noise frame whose payload spans several chunks survives the round trip, and every round
    /// of it agrees on how many bytes the decoder wants next.
    #[cfg(feature = "noise_sv2")]
    #[test]
    fn a_noise_frame_longer_than_the_read_window_is_read_over_several_rounds() {
        const PAYLOAD: usize = 2 * SV2_FRAME_CHUNK_SIZE + 7;

        let mut plain = vec![0u8; Header::SIZE + PAYLOAD];
        plain[2] = 1;
        plain[3..Header::SIZE].copy_from_slice(&(PAYLOAD as u32).to_le_bytes()[..3]);
        for (i, byte) in plain[Header::SIZE..].iter_mut().enumerate() {
            *byte = i as u8;
        }

        let (mut sender, mut receiver) = make_transport_state_pair();
        let mut encoder = NoiseEncoder::new();
        let frame = SerializedSv2Frame::<Vec<u8>>::from_bytes(plain.clone()).unwrap();
        let encrypted = encoder.encode_transport(frame, &mut sender).unwrap();
        let encrypted: &[u8] = encrypted.as_ref();

        let mut decoder = StandardNoiseDecoder::new();
        let mut offset = 0;
        let mut rounds = 0;
        let decoded = loop {
            match decoder.next_transport_frame(&mut receiver) {
                Ok(frame) => break frame,
                Err(crate::Error::MissingBytes(n)) => {
                    let writable = decoder.writable();
                    assert_eq!(n, writable.len());
                    writable.copy_from_slice(&encrypted[offset..offset + n]);
                    offset += n;
                    rounds += 1;
                }
                Err(e) => panic!("failed to decode a multi-chunk noise frame: {e:?}"),
            }
        };

        assert!(rounds > 2, "the frame should not fit in a single read");
        assert_eq!(offset, encrypted.len());
        assert_eq!(decoded.as_bytes(), &plain[..]);
    }

    /// Verifies that a single decoder instance correctly decodes two consecutive independent
    /// frames in sequence, confirming that internal state resets between frames.
    #[quickcheck]
    fn prop_decoder_multiple_frames(
        msg1: TestMessage,
        msg2: TestMessage,
        msg_type: u8,
    ) -> TestResult {
        let frame1 = match Sv2Frame::<TestMessage>::from_message(msg1.clone(), msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };
        let frame2 = match Sv2Frame::<TestMessage>::from_message(msg2.clone(), msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let mut encoder = Encoder::new();
        let encoded1 = match encoder.encode(frame1) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };
        let encoded2 = match encoder.encode(frame2) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::new();

        let decoded_msg1 = match decode_frame(&mut decoder, encoded1.as_ref(), None) {
            Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                Ok(m) => m,
                Err(_) => return TestResult::failed(),
            },
            None => return TestResult::failed(),
        };
        let decoded_msg2 = match decode_frame(&mut decoder, encoded2.as_ref(), None) {
            Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                Ok(m) => m,
                Err(_) => return TestResult::failed(),
            },
            None => return TestResult::failed(),
        };

        TestResult::from_bool(decoded_msg1 == msg1 && decoded_msg2 == msg2)
    }

    #[cfg(feature = "noise_sv2")]
    fn make_handshake_pair() -> (
        Handshake<noise_sv2::Initiator>,
        Handshake<noise_sv2::Responder>,
    ) {
        let pub_k: Secp256k1PublicKey = AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();
        let pub_k_bytes = pub_k.into_bytes();
        let priv_k: Secp256k1SecretKey = AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();
        let priv_k_bytes = priv_k.into_bytes();

        (
            Handshake::new(noise_sv2::Initiator::from_raw_k(pub_k_bytes).unwrap()),
            Handshake::new(
                noise_sv2::Responder::from_authority_kp(
                    &pub_k_bytes,
                    &priv_k_bytes,
                    Duration::from_secs(3600),
                )
                .unwrap(),
            ),
        )
    }

    #[cfg(feature = "noise_sv2")]
    fn make_transport_state_pair() -> (TransportEncryptState, TransportDecryptState) {
        let pub_k: Secp256k1PublicKey = AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();
        let pub_k_bytes = pub_k.into_bytes();
        let priv_k: Secp256k1SecretKey = AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();
        let priv_k_bytes = priv_k.into_bytes();

        let initiator = noise_sv2::Initiator::from_raw_k(pub_k_bytes).unwrap();
        let responder = noise_sv2::Responder::from_authority_kp(
            &pub_k_bytes,
            &priv_k_bytes,
            Duration::from_secs(3600),
        )
        .unwrap();

        let mut sender = Handshake::new(initiator);
        let receiver = Handshake::new(responder);

        let msg0 = sender.step_0().unwrap();
        let msg0: [u8; ELLSWIFT_ENCODING_SIZE] = msg0.payload().try_into().unwrap();

        let (msg1, receiver_transport) = receiver.step_1(msg0).unwrap();
        let msg1: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
            msg1.payload().try_into().unwrap();

        let sender_transport = sender.step_2(msg1).unwrap();
        let (sender_enc, _) = sender_transport.split();
        let (_, receiver_dec) = receiver_transport.split();
        (sender_enc, receiver_dec)
    }

    #[cfg(feature = "noise_sv2")]
    fn decode_noise_frame(
        decoder: &mut StandardNoiseDecoder,
        state: &mut TransportDecryptState,
        encoded: &[u8],
    ) -> Option<SerializedSv2Frame<Slice>> {
        let mut offset = 0;
        loop {
            let writable = decoder.writable();
            let available = encoded.len().saturating_sub(offset);
            let n = writable.len().min(available);
            writable[..n].copy_from_slice(&encoded[offset..offset + n]);
            offset += n;

            match decoder.next_transport_frame(state) {
                Ok(frame) => return Some(frame),
                Err(crate::Error::MissingBytes(_)) => {}
                Err(_) => return None,
            }
        }
    }

    /// Verifies that encrypting then decrypting a frame via `NoiseEncoder`
    /// recovers the original message, msg_type, and ext_type exactly.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_encode_decode_roundtrip(
        msg: TestMessage,
        msg_type: u8,
        ext_type: u16,
    ) -> TestResult {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let original = msg.clone();

        let sv2_frame = match Sv2Frame::<TestMessage>::from_message(msg, msg_type, ext_type, false)
        {
            Some(f) => f,
            None => return TestResult::discard(),
        };
        let expected_ext = sv2_frame.header().ext_type();

        let mut encoder = NoiseEncoder::new();
        let encrypted = match encoder.encode_transport(sv2_frame, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::new();
        let encrypted_bytes: &[u8] = encrypted.as_ref();
        match decode_noise_frame(&mut decoder, &mut receiver_state, encrypted_bytes) {
            Some(mut decoded) => {
                let header = decoded.header();
                let decoded_msg: TestMessage = match binary_sv2::from_bytes(decoded.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                };
                TestResult::from_bool(
                    decoded_msg == original
                        && header.msg_type() == msg_type
                        && header.ext_type() == expected_ext,
                )
            }
            None => TestResult::failed(),
        }
    }

    /// Verifies that `StandardNoiseDecoder` correctly handles data arriving in multiple rounds —
    /// one round per encrypted segment (header, then payload) — emitting `MissingBytes`
    /// between rounds before returning the fully decrypted frame.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_decoder_handles_partial_data(msg: TestMessage, msg_type: u8) -> TestResult {
        let frame = match Sv2Frame::<TestMessage>::from_message(msg, msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let mut encoder = NoiseEncoder::new();
        let encrypted = match encoder.encode_transport(frame, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::new();
        let encoded_bytes: &[u8] = encrypted.as_ref();
        let mut offset = 0;
        let mut missing_bytes_count = 0;

        loop {
            let writable = decoder.writable();
            let n = writable
                .len()
                .min(encoded_bytes.len().saturating_sub(offset));
            writable[..n].copy_from_slice(&encoded_bytes[offset..offset + n]);
            offset += n;

            match decoder.next_transport_frame(&mut receiver_state) {
                Ok(_) => return TestResult::from_bool(missing_bytes_count > 0),
                Err(crate::Error::MissingBytes(n)) => {
                    missing_bytes_count += 1;
                    assert!(n > 0);
                }
                Err(_) => return TestResult::failed(),
            }
        }
    }

    #[cfg(feature = "noise_sv2")]
    #[test]
    fn noise_decoder_recovers_from_a_failed_decryption() {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let frame =
            Sv2Frame::<TestMessage>::from_message(TestMessage { value: 7 }, 0, 0, false).unwrap();
        let mut encoder = NoiseEncoder::new();
        let encrypted = encoder.encode_transport(frame, &mut sender_state).unwrap();
        let encrypted: &[u8] = encrypted.as_ref();

        let mut decoder = StandardNoiseDecoder::new();

        // Fail on the encrypted header. The closure never touches `receiver_state`, so its nonce
        // stays where it was and the same bytes can be replayed below.
        let hint = decoder
            .next_transport(|_| Err(crate::Error::AeadError(noise_sv2::AeadError)))
            .unwrap_err();
        assert!(matches!(hint, crate::Error::MissingBytes(_)));
        let writable = decoder.writable();
        let len = writable.len();
        writable.copy_from_slice(&encrypted[..len]);
        let failed = decoder
            .next_transport(|_| Err(crate::Error::AeadError(noise_sv2::AeadError)))
            .unwrap_err();
        assert!(matches!(failed, crate::Error::AeadError(_)));
        assert_eq!(IsBuffer::len(&decoder.sv2_buffer), 0);
        assert!(decoder.sv2_buffer.as_ref().is_empty());

        // The same decoder must now decode the frame from the start.
        let decoded = decode_noise_frame(&mut decoder, &mut receiver_state, encrypted);
        match decoded {
            Some(mut f) => assert_eq!(
                binary_sv2::from_bytes::<TestMessage>(f.payload()).unwrap(),
                TestMessage { value: 7 }
            ),
            None => panic!("failed to decode the frame after a failed decryption"),
        }
    }

    /// Verifies that a single `StandardNoiseDecoder` instance correctly
    /// decodes two consecutive noise-encrypted frames in sequence using
    /// the same shared transport state.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_decoder_multiple_frames(
        msg1: TestMessage,
        msg2: TestMessage,
        msg_type: u8,
    ) -> TestResult {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();

        let frame1 = match Sv2Frame::<TestMessage>::from_message(msg1.clone(), msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };
        let frame2 = match Sv2Frame::<TestMessage>::from_message(msg2.clone(), msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let mut encoder = NoiseEncoder::new();

        let enc1 = match encoder.encode_transport(frame1, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };
        let enc2 = match encoder.encode_transport(frame2, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::new();

        let decoded_msg1 =
            match decode_noise_frame(&mut decoder, &mut receiver_state, enc1.as_ref()) {
                Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                },
                None => return TestResult::failed(),
            };

        let decoded_msg2 =
            match decode_noise_frame(&mut decoder, &mut receiver_state, enc2.as_ref()) {
                Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                },
                None => return TestResult::failed(),
            };

        TestResult::from_bool(decoded_msg1 == msg1 && decoded_msg2 == msg2)
    }
}
