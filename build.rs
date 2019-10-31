extern crate protobuf_codegen_pure;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR should exist");
    protobuf_codegen_pure::run(protobuf_codegen_pure::Args {
        out_dir: out_dir.as_str(),
        input: &["proto/transform.proto"],
        includes: &["proto"],
        customize: protobuf_codegen_pure::Customize {
            carllerche_bytes_for_bytes: Some(true),
            carllerche_bytes_for_string: Some(true),
            ..Default::default()
        },
    })
    .expect("protoc");

    // Work around from https://github.com/googlecartographer/point_cloud_viewer/blob/440d875f12e32dff6107233f24b5a02cf28776dc/point_viewer_proto_rust/build.rs#L33
    // https://github.com/stepancheg/rust-protobuf/issues/117
    // https://github.com/rust-lang/rust/issues/18810.
    // We open the file, add 'mod proto { mod transform { } }' around the contents and write it back. This allows us
    // to include! the file in lib.rs and have a proper proto module.
    let proto_path = Path::new(&out_dir).join("transform.rs");
    let mut contents = String::new();

    File::open(&proto_path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    let new_contents = format!("pub mod proto {{pub mod transform {{ \n{}\n}}}}", contents);

    File::create(&proto_path)
        .unwrap()
        .write_all(new_contents.as_bytes())
        .unwrap();
}
