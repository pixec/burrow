"""Builds: the digest a build reports, and the tag and build a listing names."""

from burrow import TemplateBuilder
from burrow._pb import api_pb2, common_pb2
from burrow.sandbox import _to_sandbox_info
from burrow.template import build_template, to_template_info

DIGEST = "sha256:" + "ab" * 32


class Streams:
    def server_stream(self, method, request, timeout):
        yield api_pb2.BuildLog(layer=api_pb2.BuildDone(template="t", digest="sha256:" + "cd" * 32))
        yield api_pb2.BuildLog(done=api_pb2.BuildDone(template="t", size_bytes=4, digest=DIGEST))


def test_a_build_reports_its_digest():
    built = build_template(Streams(), TemplateBuilder().from_image("alpine:3.20"), "t")
    assert (built.name, built.digest) == ("t", DIGEST)


class Recorder:
    def __init__(self):
        self.requests = []

    def server_stream(self, method, request, timeout):
        self.requests.append(request)
        yield api_pb2.BuildLog(done=api_pb2.BuildDone(template="win11", digest=DIGEST))


def test_a_disk_import_names_the_disk_its_node_and_the_tpm():
    recorder = Recorder()
    built = build_template(
        recorder, TemplateBuilder().from_disk("win.raw", "node_a", tpm=True), "win11"
    )
    request = recorder.requests[0]
    assert built.digest == DIGEST
    assert (request.from_disk, request.node_id, request.is_tpm) == ("win.raw", "node_a", True)
    assert getattr(request, "from") == ""


def test_a_listing_names_the_tag_and_the_build_it_resolves_to():
    info = to_template_info(api_pb2.TemplateInfo(name="t", tag="v1", digest=DIGEST, status="ready"))
    assert (info.tag, info.digest, info.status) == ("v1", DIGEST, "ready")
    assert _to_sandbox_info(common_pb2.Sandbox(id="s", build_digest=DIGEST)).build_digest == DIGEST
