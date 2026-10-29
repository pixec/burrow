"""Talks to burrow-guest in the spike VM over Cloud Hypervisor's hybrid vsock.

usage: python3 agent-probe.py VSOCK_UDS PROTO_DIR [handshake|health|exec ARGV...|stat PATH]

Each gRPC connection goes through a local TCP bridge that opens VSOCK_UDS and
sends `CONNECT 1024`, as burrowd does. Needs python3-grpcio and
python3-grpc-tools (Debian) for the stubs, generated from PROTO_DIR on the fly.
"""

import importlib
import os
import socket
import sys
import tempfile
import threading
import time

AGENT_PORT = 1024


def bridge(uds):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def pump(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def serve():
        while True:
            tcp, _ = srv.accept()
            vs = socket.socket(socket.AF_UNIX)
            vs.connect(uds)
            vs.sendall(b"CONNECT %d\n" % AGENT_PORT)
            line = b""
            while not line.endswith(b"\n"):
                chunk = vs.recv(1)
                if not chunk:
                    raise SystemExit(f"vsock closed during CONNECT, got {line!r}")
                line += chunk
            print("vsock:", line.decode().strip(), file=sys.stderr)
            threading.Thread(target=pump, args=(tcp, vs), daemon=True).start()
            threading.Thread(target=pump, args=(vs, tcp), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def stubs(proto_dir):
    from grpc_tools import protoc

    out = tempfile.mkdtemp()
    protos = [f for f in os.listdir(proto_dir) if f.endswith(".proto")]
    rc = protoc.main(["protoc", f"-I{proto_dir}", f"--python_out={out}", f"--grpc_python_out={out}", *protos])
    if rc:
        raise SystemExit("protoc failed")
    sys.path.insert(0, out)
    return importlib.import_module("guest_pb2"), importlib.import_module("guest_pb2_grpc")


def main():
    import grpc

    uds, proto_dir, op, *rest = sys.argv[1:]
    pb, rpc = stubs(proto_dir)
    port = bridge(uds)
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    guest = rpc.GuestStub(chan)
    t = time.monotonic()
    if op == "health":
        print(guest.Health(pb.GuestHealthRequest(), timeout=10))
    elif op == "handshake":
        net = pb.NetworkConfig(ip="172.31.250.2", prefix_len=30, gateway="172.31.250.1", dns="1.1.1.1")
        req = pb.HandshakeRequest(entropy=os.urandom(64), host_time_unix_nanos=time.time_ns(), network=net)
        print(guest.Handshake(req, timeout=30))
    elif op == "exec":
        def inputs():
            yield pb.ExecInput(start=pb.ExecStart(cmd=rest))
            yield pb.ExecInput(is_stdin_eof=True)
        for out in guest.Exec(inputs(), timeout=60):
            print(out)
    elif op == "stat":
        print(guest.Fs(pb.FsRequest(stat=pb.FsStat(path=rest[0])), timeout=10))
    else:
        raise SystemExit(f"unknown op {op}")
    print(f"{op}: {(time.monotonic() - t) * 1000:.0f} ms", file=sys.stderr)


main()
