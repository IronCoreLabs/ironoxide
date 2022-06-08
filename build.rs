use itertools::Itertools;
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR should exist");
    let name = "transform";
    protobuf_codegen::Codegen::new()
        .out_dir(&out_dir)
        .input(format!("proto/{}.proto", name))
        .include("proto")
        .customize(
            protobuf_codegen::Customize::default()
                .tokio_bytes(true)
                .tokio_bytes_for_string(true),
        )
        .pure()
        .run()
        .expect("protoc");

    // Work around from https://github.com/googlecartographer/point_cloud_viewer/blob/440d875f12e32dff6107233f24b5a02cf28776dc/point_viewer_proto_rust/build.rs#L33
    // https://github.com/stepancheg/rust-protobuf/issues/117
    // https://github.com/rust-lang/rust/issues/18810.
    // We open the file, add 'mod proto { mod transform { } }' around the contents and write it back. This allows us
    // to include! the file in lib.rs and have a proper proto module.
    let proto_path = Path::new(&out_dir).join(format!("{}.rs", name));
    let mut contents = String::new();

    File::open(&proto_path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();

    // Work around for https://github.com/rust-lang/rust/issues/54726
    // Introduced in rust-protobuf https://github.com/stepancheg/rust-protobuf/pull/495
    // More discussion: https://github.com/stepancheg/rust-protobuf/pull/523#issuecomment-701026992
    let filtered: String = contents
        .lines()
        .filter(|line| line.trim() != "#![rustfmt::skip]")
        .join("\n");

    let new_contents = format!("mod proto {{pub mod {} {{ \n{}\n}}}}", name, filtered);

    File::create(&proto_path)
        .unwrap()
        .write_all(new_contents.as_bytes())
        .unwrap();
}
