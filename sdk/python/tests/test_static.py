# The class-level helpers open a connection of their own: `call_timeout` is
# that connection's default, and `timeout` reaches the call they make.

import pytest

import burrow.client
from burrow import Sandbox, Template
from burrow._pb import api_pb2, common_pb2


class Recorder:
    made = []

    def __init__(self, *, timeout, **_):
        self.timeout = timeout
        self.calls = []
        Recorder.made.append(self)

    def unary(self, method, request, timeout):
        self.calls.append((method, timeout))
        return common_pb2.Sandbox(id="sbx_test")

    def server_stream(self, method, request, timeout):
        self.calls.append((method, timeout))
        return iter([api_pb2.BuildLog(done=api_pb2.BuildDone(template="t"))])

    def retain(self):
        return self

    def close(self):
        pass


@pytest.fixture
def recorder(monkeypatch):
    Recorder.made = []
    monkeypatch.setattr(burrow.client, "Transport", Recorder)
    return Recorder.made


def test_create_waits_past_the_connection_default(recorder):
    Sandbox.create(template="python", timeout=600, call_timeout=5)
    assert recorder[0].timeout == 5
    assert recorder[0].calls == [("CreateSandbox", 600)]


def test_create_waits_two_minutes_by_default(recorder):
    Sandbox.create(template="python")
    assert recorder[0].timeout == 60
    assert recorder[0].calls == [("CreateSandbox", 120)]


def test_build_takes_its_own_deadline(recorder):
    Template.build(Template().from_image("python:3.12"), "t", timeout=3600, call_timeout=5)
    assert recorder[0].timeout == 5
    assert recorder[0].calls == [("BuildTemplate", 3600)]
