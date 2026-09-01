extern crate alloc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use framing_sv2::framing::Sv2Frame;

use codec_sv2::Encoder;

#[cfg(feature = "noise_sv2")]
use codec_sv2::NoiseEncoder;

mod common;
use common::TestMsg;

fn bench_plain_encoder(c: &mut Criterion) {
    c.bench_function("encoder/plain", |b| {
        let msg = TestMsg { data: 42u8 };
        let mut enc = Encoder::new();
        b.iter(|| {
            let frame = Sv2Frame::from_message(msg.clone(), 0, 0, true).unwrap();
            let out = enc.encode(black_box(frame)).unwrap();
            black_box(out);
        })
    });
}

fn bench_encoder_creation(c: &mut Criterion) {
    c.bench_function("encoder/creation/plain", |b| {
        b.iter(|| {
            let enc = Encoder::new();
            black_box(enc);
        })
    });
}

#[cfg(feature = "noise_sv2")]
use common::make_transport_state_pair as setup_noise_states;

#[cfg(feature = "noise_sv2")]
fn bench_noise_encoder_transport(c: &mut Criterion) {
    c.bench_function("encoder/noise/transport", |b| {
        let (mut state, _) = setup_noise_states();
        let msg = TestMsg { data: 42u8 };
        let mut enc = NoiseEncoder::new();

        b.iter(|| {
            let frame = Sv2Frame::from_message(msg.clone(), 0, 0, true).unwrap();
            let out = enc.encode_transport(black_box(frame), &mut state).unwrap();
            black_box(out);
        })
    });
}

#[cfg(feature = "noise_sv2")]
fn bench_noise_encoder_creation(c: &mut Criterion) {
    c.bench_function("encoder/creation/noise", |b| {
        b.iter(|| {
            let enc = NoiseEncoder::new();
            black_box(enc);
        })
    });
}

#[cfg(feature = "noise_sv2")]
fn bench_noise_handshake(c: &mut Criterion) {
    c.bench_function("encoder/noise/handshake/complete", |b| {
        b.iter(|| {
            let (sender, receiver) = common::make_handshake_pair();

            let (first_message, sender) = sender.step_0().unwrap();
            let first_message_bytes: [u8; noise_sv2::ELLSWIFT_ENCODING_SIZE] =
                first_message.payload().try_into().unwrap();

            let (second_message, receiver_transport) =
                receiver.step_1(first_message_bytes).unwrap();
            let second_message_bytes: [u8; noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
                second_message.payload().try_into().unwrap();

            let sender_transport = sender.step_2(second_message_bytes).unwrap();
            black_box((sender_transport, receiver_transport));
        })
    });
}

#[cfg(feature = "noise_sv2")]
criterion_group!(
    encoder_benches,
    bench_plain_encoder,
    bench_encoder_creation,
    bench_noise_encoder_transport,
    bench_noise_encoder_creation,
    bench_noise_handshake
);

#[cfg(not(feature = "noise_sv2"))]
criterion_group!(encoder_benches, bench_plain_encoder, bench_encoder_creation);

criterion_main!(encoder_benches);
