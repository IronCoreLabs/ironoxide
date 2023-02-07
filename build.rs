fn main() {
    let name = "transform";
    protobuf_codegen::Codegen::new()
        .cargo_out_dir("proto")
        .input(format!("proto/{name}.proto"))
        .include("proto")
        .customize(
            protobuf_codegen::Customize::default()
                .tokio_bytes(true)
                .tokio_bytes_for_string(true),
        )
        .pure()
        .run()
        .expect("protoc");
}
