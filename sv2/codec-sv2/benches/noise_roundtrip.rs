extern crate alloc;

#[cfg(feature = "noise_sv2")]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

#[cfg(feature = "noise_sv2")]
use codec_sv2::{
    Handshake, NoiseEncoder, StandardNoiseDecoder, TransportDecryptState, TransportEncryptState,
};

#[cfg(feature = "noise_sv2")]
use framing_sv2::framing::Sv2Frame;

#[cfg(feature = "noise_sv2")]
use noise_sv2::{Initiator, Responder};

#[cfg(feature = "noise_sv2")]
mod common;
#[cfg(feature = "noise_sv2")]
use common::TestMsg;

#[cfg(feature = "noise_sv2")]
fn setup_noise_engine_pair() -> (
    NoiseEncoder,
    StandardNoiseDecoder,
    TransportEncryptState,
    TransportDecryptState,
) {
    use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

    const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const AUTHORITY_PRIVATE_K: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
    const CERT_VALIDITY: core::time::Duration = core::time::Duration::from_secs(3600);

    let authority_public_k: Secp256k1PublicKey = AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();

    let authority_private_k: Secp256k1SecretKey =
        AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();

    let initiator = Initiator::from_raw_k(authority_public_k.into_bytes()).unwrap();
    let responder = Responder::from_authority_kp(
        &authority_public_k.into_bytes(),
        &authority_private_k.into_bytes(),
        CERT_VALIDITY,
    )
    .unwrap();

    let mut sender = Handshake::new(initiator);
    let receiver = Handshake::new(responder);

    let first_message = sender.step_0().unwrap();
    let first_message_bytes: [u8; noise_sv2::ELLSWIFT_ENCODING_SIZE] =
        first_message.payload().try_into().unwrap();

    let (second_message, receiver_transport) = receiver.step_1(first_message_bytes).unwrap();
    let second_message_bytes: [u8; noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
        second_message.payload().try_into().unwrap();

    let sender_transport = sender.step_2(second_message_bytes).unwrap();

    let enc = NoiseEncoder::new();
    let dec = StandardNoiseDecoder::new();

    let (sender_encrypt, _) = sender_transport.split();
    let (_, receiver_decrypt) = receiver_transport.split();
    (enc, dec, sender_encrypt, receiver_decrypt)
}

#[cfg(feature = "noise_sv2")]
fn bench_noise_roundtrip(c: &mut Criterion) {
    c.bench_function("noise/roundtrip", |b| {
        let msg = TestMsg { data: 9u8 };

        b.iter(|| {
            // Set up fresh Noise engines for each iteration (their state cannot be reused).
            let (mut enc, _, mut enc_state, mut dec_state) = setup_noise_engine_pair();

            // Encode
            let frame = Sv2Frame::from_message(msg.clone(), 0, 0, true).unwrap();
            let encrypted = enc
                .encode_transport(black_box(frame), &mut enc_state)
                .unwrap();

            // Decode
            let mut dec = StandardNoiseDecoder::new();
            let w = dec.writable();
            let len = w.len();
            w[..len].copy_from_slice(&encrypted[0..len]);
            let mut offset = len;

            loop {
                match dec.next_transport_frame(&mut dec_state) {
                    Ok(decoded) => {
                        black_box(decoded);
                        break;
                    }
                    Err(codec_sv2::Error::MissingBytes(_)) => {
                        let w = dec.writable();
                        let n = w.len();
                        w.copy_from_slice(&encrypted[offset..offset + n]);
                        offset += n;
                    }
                    Err(e) => panic!("Decode error: {:?}", e),
                }
            }
        })
    });
}

#[cfg(feature = "noise_sv2")]
fn bench_noise_encode_only(c: &mut Criterion) {
    c.bench_function("noise/encode_only", |b| {
        let (mut enc, _, mut enc_state, _) = setup_noise_engine_pair();

        let msg = TestMsg { data: 42u8 };

        b.iter(|| {
            let frame = Sv2Frame::from_message(msg.clone(), 0, 0, true).unwrap();
            let encrypted = enc
                .encode_transport(black_box(frame), &mut enc_state)
                .unwrap();
            black_box(encrypted);
        })
    });
}

// Benchmarks calculating the encrypted length of a payload from its header
#[cfg(feature = "noise_sv2")]
fn bench_encrypted_payload_length(c: &mut Criterion) {
    use framing_sv2::header::Header;

    let mut group = c.benchmark_group("noise/encrypted_payload_length");

    for &size in &[64usize, 1024, 16384, 61440, 16_777_215] {
        let mut header_bytes = vec![0u8; 6];
        header_bytes[3..6].copy_from_slice(&(size as u32).to_le_bytes()[..3]);
        let header = Header::from_bytes(&header_bytes).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| black_box(codec_sv2::encrypted_payload_length(&header)))
        });
    }

    group.finish();
}

#[cfg(feature = "noise_sv2")]
fn bench_noise_handshake_steps(c: &mut Criterion) {
    use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

    const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const AUTHORITY_PRIVATE_K: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
    const CERT_VALIDITY: core::time::Duration = core::time::Duration::from_secs(3600);

    c.bench_function("noise/handshake/step_0", |b| {
        b.iter(|| {
            let authority_public_k: Secp256k1PublicKey =
                AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();

            let initiator = Initiator::from_raw_k(authority_public_k.into_bytes()).unwrap();
            let mut sender = Handshake::new(initiator);

            let first_message = sender.step_0().unwrap();
            black_box(first_message);
        })
    });

    c.bench_function("noise/handshake/step_1", |b| {
        let authority_public_k: Secp256k1PublicKey =
            AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();

        let authority_private_k: Secp256k1SecretKey =
            AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();

        let initiator = Initiator::from_raw_k(authority_public_k.into_bytes()).unwrap();
        let mut sender = Handshake::new(initiator);

        let first_message = sender.step_0().unwrap();
        let first_message_bytes: [u8; noise_sv2::ELLSWIFT_ENCODING_SIZE] =
            first_message.payload().try_into().unwrap();

        b.iter(|| {
            let responder = Responder::from_authority_kp(
                &authority_public_k.into_bytes(),
                &authority_private_k.into_bytes(),
                CERT_VALIDITY,
            )
            .unwrap();

            let receiver = Handshake::new(responder);
            let (second_message, _) = receiver.step_1(first_message_bytes).unwrap();
            black_box(second_message);
        })
    });
}

#[cfg(feature = "noise_sv2")]
criterion_group!(
    noise_benches,
    bench_noise_roundtrip,
    bench_noise_encode_only,
    bench_noise_handshake_steps,
    bench_encrypted_payload_length
);

#[cfg(feature = "noise_sv2")]
criterion_main!(noise_benches);

#[cfg(not(feature = "noise_sv2"))]
fn main() {
    eprintln!("Noise benchmarks require the 'noise_sv2' feature");
}
