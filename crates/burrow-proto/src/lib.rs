pub mod common {
    pub mod v1 {
        tonic::include_proto!("burrow.common.v1");
    }
}

pub mod api {
    pub mod v1 {
        tonic::include_proto!("burrow.api.v1");
    }
}

pub mod node {
    pub mod v1 {
        tonic::include_proto!("burrow.node.v1");
    }
}

pub mod agent {
    pub mod v1 {
        tonic::include_proto!("burrow.agent.v1");
    }
}

/// The `.proto` files the TypeScript SDK ships.
///
/// They have to be *copies*: the SDK is published as an npm package and loads
/// them at runtime, so it cannot reach into this crate's directory. Copies
/// drift, though. These did, silently, for several fields, and a contract
/// that has quietly diverged is worse than one that never existed, because
/// both sides believe they agree.
///
/// So the copies are checked rather than trusted. `cargo xtask protos` writes
/// them; this test fails if anyone changes a proto without running it.
#[cfg(test)]
mod sdk_protos {
    use std::path::PathBuf;

    /// Every proto the SDKs carry, including `node` and `agent`: they are not
    /// used by an SDK today, but a stale copy is a trap for whoever reaches
    /// for one next.
    const SHIPPED: [&str; 4] = ["common", "api", "node", "agent"];

    const SDK_DIRS: [&str; 2] = [
        "../../sdk/typescript/proto",
        "../../sdk/python/src/burrow/proto",
    ];

    fn source_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto")
    }

    #[test]
    fn the_sdk_copies_match_the_source() {
        let mut stale = Vec::new();
        for dir in SDK_DIRS {
            for name in SHIPPED {
                let file = format!("{name}.proto");
                let source = std::fs::read_to_string(source_dir().join(&file))
                    .unwrap_or_else(|err| panic!("reading {file}: {err}"));
                let sdk = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);
                let shipped = match std::fs::read_to_string(sdk.join(&file)) {
                    Ok(text) => text,
                    Err(_) => {
                        stale.push(format!("{dir}/{file} (missing from the SDK)"));
                        continue;
                    }
                };
                if source != shipped {
                    stale.push(format!("{dir}/{file}"));
                }
            }
        }

        assert!(
            stale.is_empty(),
            "the SDK's proto copies have drifted from this crate's: {}.\n\
             Run `cargo xtask protos` to update them.",
            stale.join(", ")
        );
    }
}
