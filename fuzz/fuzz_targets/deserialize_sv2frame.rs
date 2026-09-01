#![no_main]
use framing_sv2::framing::{EncodableFrame, SerializedSv2Frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    if let Ok(frame) = SerializedSv2Frame::<Vec<u8>>::from_bytes(data.clone()) {
        let mut serialized = vec![0u8; frame.encoded_length()];
        frame.encode_into(&mut serialized).unwrap();
        assert_eq!(serialized, data);

        let frame2 = SerializedSv2Frame::<Vec<u8>>::from_bytes(serialized.clone()).unwrap();
        let mut serialized2 = vec![0u8; frame2.encoded_length()];
        frame2.encode_into(&mut serialized2).unwrap();

        assert_eq!(serialized, serialized2);
    }
});
