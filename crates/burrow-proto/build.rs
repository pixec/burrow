fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored protoc so builds need no system protobuf on macOS or Linux.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_build::configure().compile_protos(
        &[
            "proto/common.proto",
            "proto/api.proto",
            "proto/node.proto",
            "proto/agent.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
