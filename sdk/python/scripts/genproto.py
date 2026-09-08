"""Regenerates burrow/_pb from burrow/proto.

Run after `cargo xtask protos` updates the copies here:

    python scripts/genproto.py

`--check` reports drift and exits non-zero instead of writing, which is the
CI form (mirroring `cargo xtask protos --check` for the .proto copies).

The generated modules are committed, so installing the SDK needs neither
protoc nor grpcio-tools; only regenerating does.
"""

import importlib.metadata
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTO = ROOT / "src" / "burrow" / "proto"
OUT = ROOT / "src" / "burrow" / "_pb"

# The SDK talks only to the public control-plane API.
FILES = ["common.proto", "api.proto"]

# The generator decides the runtime floors the generated modules enforce at
# import: grpcio-tools 1.80 emits a `_pb` that refuses grpcio<1.80 and
# validates protobuf 6.31.1. Regenerating with a different minor moves those
# floors without touching pyproject.toml, so the two are pinned together.
GRPCIO_TOOLS = "1.80"


def check_toolchain() -> None:
    """Fails unless grpcio-tools matches the pin in pyproject.toml's `dev`."""
    version = importlib.metadata.version("grpcio-tools")
    if not version.startswith(f"{GRPCIO_TOOLS}."):
        sys.exit(
            f"grpcio-tools {version} does not match the pinned {GRPCIO_TOOLS}.x; "
            f"the generated code would enforce different runtime floors than "
            f"pyproject.toml declares. Install with: pip install -e '.[dev]'"
        )


def generate(out: pathlib.Path) -> None:
    """Writes the generated modules into `out`."""
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"-I{PROTO}",
            f"--python_out={out}",
            f"--grpc_python_out={out}",
            *FILES,
        ],
        check=True,
    )
    # protoc emits absolute imports between the generated modules
    # (`import common_pb2`), which only work at the top level; the package
    # needs them relative.
    for path in out.glob("*_pb2*.py"):
        text = path.read_text()
        text = re.sub(
            r"^import (\w+_pb2) as",
            r"from . import \1 as",
            text,
            flags=re.MULTILINE,
        )
        path.write_text(text)
    (out / "__init__.py").write_text(
        '"""Generated protobuf/gRPC modules. Regenerate with scripts/genproto.py."""\n'
    )


def check() -> None:
    """Fails when the committed modules are not what the protos generate.

    A `.proto` change that never got regenerated ships an SDK that disagrees
    with the server about the wire, and nothing else notices: the stale modules
    import and run perfectly well.
    """
    with tempfile.TemporaryDirectory() as tmp:
        fresh = pathlib.Path(tmp) / "_pb"
        generate(fresh)
        stale = []
        for path in sorted(fresh.glob("*.py")):
            have = OUT / path.name
            if not have.exists() or have.read_bytes() != path.read_bytes():
                stale.append(path.name)
        # A file that is committed but no longer generated is drift too.
        for path in sorted(OUT.glob("*.py")):
            if not (fresh / path.name).exists():
                stale.append(f"{path.name} (no longer generated)")
    if stale:
        sys.exit(
            f"{OUT} has drifted from {PROTO}: {', '.join(stale)}. "
            f"Run `python sdk/python/scripts/genproto.py`."
        )
    print(f"{OUT} is in sync")


def main() -> None:
    check_toolchain()
    if "--check" in sys.argv[1:]:
        check()
        return
    generate(OUT)
    print(f"generated {', '.join(FILES)} into {OUT}")


if __name__ == "__main__":
    main()
