use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ironoxide::config::IronOxideConfig;
use ironoxide::{
    document::{advanced::DocumentAdvancedOps, DocumentEncryptOpts},
    prelude::*,
    DeviceContext, IronOxide,
};

/// Setup for dev1 environment
fn setup_dev() -> IronOxide {
    let device_string = std::fs::read_to_string("benches/data/dev1-device1.json")
        .expect("device missing. Did you decrypt the .iron file?");
    let d: DeviceContext = serde_json::from_str(&device_string).expect("DeviceContext invalid");
    ironoxide::initialize(&d, &IronOxideConfig::default()).expect("ironoxide init failed")
}

fn criterion_benchmark(c: &mut Criterion) {
    let io = setup_dev();
    let data = [43u8; 100 * 1024]; //100KB of data

    // encrypted data to user to decrypt
    let enc_result = io
        .document_encrypt(&data, &Default::default())
        .expect("encryption failed");
    let enc_data = enc_result.encrypted_data();

    // (unmanaged) encrypted data/deks to user to decrypt
    let enc_result_unmanaged = io
        .document_encrypt_unmanaged(&data, &Default::default())
        .expect("encryption failed");
    let (enc_data_unmanaged, enc_deks_unmanaged) = (
        enc_result_unmanaged.encrypted_data(),
        enc_result_unmanaged.encrypted_deks(),
    );

    // group to encrypt to
    let group_result = io
        .group_create(&Default::default())
        .expect("group creation failed");
    let group = group_result.id();

    // data encrypted to a group to decrypt
    let group_enc_result = io
        .document_encrypt_unmanaged(
            &data,
            &DocumentEncryptOpts::with_explicit_grants(None, None, false, vec![group.into()]),
        )
        .expect("encrypt to group failed");
    let (group_enc_data, group_enc_deks) = (
        group_enc_result.encrypted_data(),
        group_enc_result.encrypted_deks(),
    );

    c.bench_function("document get metadata", |b| {
        b.iter(|| io.document_get_metadata(black_box(enc_result.id())))
    });

    c.bench_function("document encrypt [self]", |b| {
        b.iter(|| io.document_encrypt(black_box(&data), &Default::default()))
    });

    c.bench_function("document encrypt (unmanaged) [self]", |b| {
        b.iter(|| io.document_encrypt_unmanaged(black_box(&data), &Default::default()))
    });

    c.bench_function("document decrypt [user]", |b| {
        b.iter(|| io.document_decrypt(black_box(enc_data)))
    });

    c.bench_function("document decrypt (unmanaged) [group]", |b| {
        b.iter(|| {
            io.document_decrypt_unmanaged(black_box(&group_enc_data), black_box(&group_enc_deks))
        })
    });

    c.bench_function("document decrypt (unmanaged) [user]", |b| {
        b.iter(|| {
            io.document_decrypt_unmanaged(
                black_box(enc_data_unmanaged),
                black_box(enc_deks_unmanaged),
            )
        })
    });

    c.bench_function("group create", |b| {
        b.iter(|| io.group_create(black_box(&Default::default())))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
);
criterion_main!(benches);
