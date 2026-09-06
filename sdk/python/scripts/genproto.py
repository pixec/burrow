"""Regenerates burrow/_pb from burrow/proto.

Run after `cargo xtask protos` updates the copies here:

    python scripts/genproto.py

The generated modules are committed, so installing the SDK needs neither
protoc nor grpcio-tools; only regenerating does.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTO = ROOT / "src" / "burrow" / "proto"
OUT = ROOT / "src" / "burrow" / "_pb"

# The SDK talks only to the public control-plane API.
FILES = ["common.proto", "api.proto"]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"-I{PROTO}",
            f"--python_out={OUT}",
            f"--grpc_python_out={OUT}",
            *FILES,
        ],
        check=True,
    )
    # protoc emits absolute imports between the generated modules
    # (`import common_pb2`), which only work at the top level; the package
    # needs them relative.
    for path in OUT.glob("*_pb2*.py"):
        text = path.read_text()
        text = re.sub(
            r"^import (\w+_pb2) as",
            r"from . import \1 as",
            text,
            flags=re.MULTILINE,
        )
        path.write_text(text)
    (OUT / "__init__.py").write_text(
        '"""Generated protobuf/gRPC modules. Regenerate with scripts/genproto.py."""\n'
    )
    print(f"generated {', '.join(FILES)} into {OUT}")


if __name__ == "__main__":
    main()
