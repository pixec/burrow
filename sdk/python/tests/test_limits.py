# A full file chunk over a real connection, on both routes: relayed through a
# stand-in orchestrator, and direct to a stand-in node it grants.

import time
from concurrent import futures

import grpc
import pytest

from burrow._pb import api_pb2, api_pb2_grpc
from burrow._transport import MAX_FILE_CHUNK, MAX_MESSAGE_BYTES, Transport
from burrow.errors import BurrowError


def _fs(request, context):
    """Answers Fs as a guest would: writes report their length, reads fill it."""
    if request.WhichOneof("op") == "write":
        return api_pb2.FsResponse(written=len(request.write.data))
    return api_pb2.FsResponse(data=b"\1" * request.read.length)


class _Orchestrator(api_pb2_grpc.BurrowServicer):
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def Fs(self, request, context):
        return _fs(request, context)

    def IssueAccess(self, request, context):
        return api_pb2.AccessGrant(
            endpoint=self.endpoint,
            token="t",
            sandbox_id=request.sandbox_id,
            expires_at_unix_ms=int(time.time() * 1000) + 600_000,
        )


class _Node(api_pb2_grpc.AccessServicer):
    def Fs(self, request, context):
        return _fs(request, context)


@pytest.fixture
def endpoint():
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=[
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        ],
    )
    port = server.add_insecure_port("127.0.0.1:0")
    endpoint = f"http://127.0.0.1:{port}"
    api_pb2_grpc.add_BurrowServicer_to_server(_Orchestrator(endpoint), server)
    api_pb2_grpc.add_AccessServicer_to_server(_Node(), server)
    server.start()
    yield endpoint
    server.stop(None)


@pytest.mark.parametrize("route", ["orchestrator", "direct"])
def test_a_full_chunk_is_written_and_read_in_one_call(endpoint, route):
    transport = Transport(endpoint=endpoint, route=route)
    try:
        target = transport.route("sbx_a")
        written = target.unary(
            "Fs",
            api_pb2.FsRequest(
                sandbox_id="sbx_a",
                write=api_pb2.FsWrite(handle=1, data=bytes(MAX_FILE_CHUNK)),
            ),
        )
        assert written.written == MAX_FILE_CHUNK
        read = target.unary(
            "Fs",
            api_pb2.FsRequest(
                sandbox_id="sbx_a",
                read=api_pb2.FsRead(handle=1, length=MAX_FILE_CHUNK),
            ),
        )
        assert len(read.data) == MAX_FILE_CHUNK
    finally:
        transport.close()


def test_a_message_past_the_limit_is_refused(endpoint):
    transport = Transport(endpoint=endpoint, route="orchestrator")
    try:
        with pytest.raises(BurrowError) as err:
            transport.unary(
                "Fs",
                api_pb2.FsRequest(
                    sandbox_id="sbx_a",
                    write=api_pb2.FsWrite(handle=1, data=bytes(MAX_MESSAGE_BYTES)),
                ),
            )
        assert err.value.code == "resource_exhausted"
    finally:
        transport.close()
