// Build script for CHAKRAVYUH — compile protobuf definitions for gRPC.
// RELEASE FIX: Eliminates panic on missing protoc. Emits structured
// diagnostics and exits gracefully so CI logs are actionable.

fn ensure_protoc() -> Result<String, String> {
    // 1. Explicit PROTOC env var takes precedence.
    if let Ok(p) = std::env::var("PROTOC") {
        if std::path::Path::new(&p).exists() {
            return Ok(p);
        }
        return Err(format!("PROTOC env var points to non-existent path: {}", p));
    }

    // 2. Check PATH for system protoc.
    if let Ok(output) = std::process::Command::new("protoc")
        .arg("--version")
        .output()
    {
        if output.status.success() {
            return Ok("protoc".to_string());
        }
    }

    // 3. Try vendored protoc at known registry paths.
    let vendored_candidates = [
        // protoc-bin-vendored-linux-x86_64 (common versions)
        "/home/z/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/protoc-bin-vendored-linux-x86_64-3.2.0/bin/protoc",
        // Add other platforms/versions as needed.
    ];
    for candidate in &vendored_candidates {
        if std::path::Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }

    Err(
        "protoc not found. Install it via `apt-get install protobuf-compiler`, \
        `brew install protobuf`, or set the PROTOC env var. \
        See https://docs.rs/prost-build/#sourcing-protoc for details."
            .to_string(),
    )
}

fn main() {
    let protoc = match ensure_protoc() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("cargo:error={}", msg);
            // Exit with non-zero status; do NOT panic.
            std::process::exit(1);
        }
    };
    std::env::set_var("PROTOC", &protoc);

    if let Err(e) = tonic_build::compile_protos("proto/chakravyuh.proto") {
        eprintln!("cargo:error=failed to compile protobuf: {}", e);
        std::process::exit(1);
    }
}
