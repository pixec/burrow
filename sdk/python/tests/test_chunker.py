from burrow._pb import api_pb2
from burrow.sandbox import _Chunker, _collect


def _feed(messages):
    chunker = _Chunker()
    for msg in messages:
        yield from chunker.feed(msg)


def test_a_character_split_across_chunks_arrives_whole():
    euro = "€".encode()
    chunks = list(
        _feed(
            [
                api_pb2.ExecOutput(stdout=b"price " + euro[:1]),
                api_pb2.ExecOutput(stdout=euro[1:] + b"5"),
                api_pb2.ExecOutput(exit_code=0),
            ]
        )
    )
    text = "".join(chunk.data for chunk in chunks if chunk.type == "stdout")
    assert text == "price €5"
    assert b"".join(chunk.raw for chunk in chunks if chunk.type == "stdout") == (
        b"price " + euro + b"5"
    )


def test_bytes_that_are_not_text_come_back_exactly():
    blob = bytes(range(256))
    result = _collect(
        _feed([api_pb2.ExecOutput(stdout=blob), api_pb2.ExecOutput(exit_code=0)])
    )
    assert result.stdout_bytes == blob


def test_an_exit_a_signal_caused_names_it():
    result = _collect(
        _feed([api_pb2.ExecOutput(exit_signal=15), api_pb2.ExecOutput(exit_code=143)])
    )
    assert (result.exit_code, result.exit_signal, result.success) == (143, 15, False)


def test_output_the_sandbox_does_not_have_is_reported():
    chunks = list(
        _feed([api_pb2.ExecOutput(lost_bytes=42), api_pb2.ExecOutput(stdout=b"tail")])
    )
    assert chunks[0].type == "lost" and chunks[0].lost_bytes == 42
    assert chunks[1].data == "tail"
