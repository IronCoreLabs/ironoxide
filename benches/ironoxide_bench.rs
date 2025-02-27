use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ironoxide::prelude::*;
use lazy_static::*;
use tokio::runtime::Runtime;

lazy_static! {
    /// The ICL environment to run benchmarks against.
    ///
    /// Reads from the environment variable IRONCORE_ENV. Supports `stage`, and `prod`.
    /// An unset environment variable will be interpreted as `stage`.
    /// An invalid environment variable will result in a panic.
    pub static ref ENV: String = match std::env::var("IRONCORE_ENV") {
        Ok(url) => match url.to_lowercase().as_str() {
            "stage" => "stage",
            "prod" => "prod",
            _ => panic!("IRONCORE_ENV can only be set to `stage` or `prod` when running the benchmarks.")
        },
        _ => {
            // The core code defaults to `prod`, so we have to set this so the API_URL is set correctly.
            unsafe {
                std::env::set_var("IRONCORE_ENV", "stage");
            }
            "stage"
        },
    }
    .to_string();
}

/// Setup for environment
async fn setup_env() -> IronOxide {
    let filename = format!("benches/data/{}-device1.json", *ENV);
    let device_string = std::fs::read_to_string(filename.clone()).unwrap_or_else(|_| {
        panic!(
            "Device missing for {}. Did you decrypt the .iron file?",
            *ENV
        )
    });
    let d: DeviceContext = serde_json::from_str(&device_string)
        .unwrap_or_else(|_| panic!("Invalid DeviceContext in {}.", filename));
    ironoxide::initialize(&d, &IronOxideConfig::default())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to initialize IronOxide using the device in {}.",
                filename
            )
        })
}

fn criterion_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().expect("Tokio Runtime init failed");
    let f = async {
        let io = setup_env().await;
        let data = [43u8; 100 * 1024]; //100KB of data

        // encrypted data to user to decrypt
        let enc_result = io
            .document_encrypt(data.into(), &Default::default())
            .await
            .expect("encryption failed");
        let enc_data = enc_result.encrypted_data().to_vec();

        // (unmanaged) encrypted data/deks to user to decrypt
        let enc_result_unmanaged = io
            .document_encrypt_unmanaged(data.into(), &Default::default())
            .await
            .expect("encryption failed");
        let (enc_data_unmanaged, enc_deks_unmanaged) = (
            enc_result_unmanaged.encrypted_data().to_vec(),
            enc_result_unmanaged.encrypted_deks().to_vec(),
        );

        // group to encrypt to
        let group_result = io
            .group_create(&Default::default())
            .await
            .expect("group creation failed");
        let group1 = group_result.id();

        // another group to encrypt to
        let group_result2 = io
            .group_create(&Default::default())
            .await
            .expect("group creation failed");
        let group2 = group_result2.id();

        // data encrypted to a group to decrypt
        let group_enc_result = io
            .document_encrypt_unmanaged(
                data.into(),
                &DocumentEncryptOpts::with_explicit_grants(None, None, false, vec![group1.into()]),
            )
            .await
            .expect("encrypt to group failed");
        let (group_enc_data, group_enc_deks) = (
            group_enc_result.encrypted_data().to_vec(),
            group_enc_result.encrypted_deks().to_vec(),
        );

        (
            io,
            data,
            enc_result,
            enc_data,
            enc_data_unmanaged,
            enc_deks_unmanaged,
            group_enc_data,
            group_enc_deks,
            group1.clone(),
            group2.clone(),
        )
    };
    let (
        io,
        data,
        enc_result,
        enc_data,
        enc_data_unmanaged,
        enc_deks_unmanaged,
        group_enc_data,
        group_enc_deks,
        group1,
        group2,
    ) = rt.block_on(f);

    c.bench_function("document get metadata", |b| {
        b.iter(|| rt.block_on(io.document_get_metadata(black_box(enc_result.id()))))
    });

    c.bench_function("document encrypt [self]", |b| {
        b.iter(|| rt.block_on(io.document_encrypt(black_box(data.into()), &Default::default())))
    });

    c.bench_function("document encrypt (unmanaged) [self]", |b| {
        b.iter(|| {
            rt.block_on(io.document_encrypt_unmanaged(black_box(data.into()), &Default::default()))
        })
    });

    c.bench_function("document encrypt [self, group]", |b| {
        b.iter(|| {
            let opts = DocumentEncryptOpts::with_explicit_grants(
                None,
                None,
                true,
                vec![group1.clone().into()],
            );
            rt.block_on(io.document_encrypt(black_box(data.into()), &opts))
        })
    });

    c.bench_function("document encrypt [self, group x 2]", |b| {
        b.iter(|| {
            let opts = DocumentEncryptOpts::with_explicit_grants(
                None,
                None,
                true,
                vec![group1.clone().into(), group2.clone().into()],
            );
            rt.block_on(io.document_encrypt(black_box(data.into()), &opts))
        })
    });

    c.bench_function("document decrypt [user]", |b| {
        b.iter(|| rt.block_on(io.document_decrypt(black_box(&enc_data))))
    });

    c.bench_function("document decrypt (unmanaged) [group]", |b| {
        b.iter(|| {
            rt.block_on(
                io.document_decrypt_unmanaged(
                    black_box(&group_enc_data),
                    black_box(&group_enc_deks),
                ),
            )
        })
    });

    c.bench_function("document decrypt (unmanaged) [user]", |b| {
        b.iter(|| {
            rt.block_on(io.document_decrypt_unmanaged(
                black_box(&enc_data_unmanaged),
                black_box(&enc_deks_unmanaged),
            ))
        })
    });

    c.bench_function("group create", |b| {
        b.iter(|| rt.block_on(io.group_create(black_box(&Default::default()))))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
);
criterion_main!(benches);
