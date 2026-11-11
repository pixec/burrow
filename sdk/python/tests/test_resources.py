"""Reshaping a sandbox and moving its clocks, as the calls go out and their
answers come back."""

import pytest

from burrow import BurrowError, ResourceOutcome, ResourcesUpdate
from burrow._pb import api_pb2, common_pb2


def answering(transport, response):
    calls = []

    def unary(method, request, timeout=None):
        calls.append((method, request))
        return response

    transport.unary = unary
    return calls


def test_a_resources_update_names_its_fields_and_reads_back_each_outcome(transport, sandbox):
    calls = answering(
        transport,
        api_pb2.UpdateResourcesResponse(
            sandbox=common_pb2.Sandbox(
                id="sbx_test",
                policy=common_pb2.Policy(resources=common_pb2.ResourcePolicy(disk_mib=1024)),
            ),
            vcpus=api_pb2.ResourceOutcome(
                change=api_pb2.RESOURCE_CHANGE_NEXT_BOOT, previous=1, value=2
            ),
            mem_mib=api_pb2.ResourceOutcome(
                change=api_pb2.RESOURCE_CHANGE_REFUSED, previous=512, value=512, reason="no"
            ),
            disk_mib=api_pb2.ResourceOutcome(
                change=api_pb2.RESOURCE_CHANGE_OFFLINE, previous=2048, value=1024
            ),
            filesystem_bytes=1 << 30,
        ),
    )
    updated = sandbox.update_resources(vcpus=2, memory_mib=1024, disk_mib=1024)
    method, request = calls[0]
    assert method == "UpdateResources"
    assert request.sandbox_id == "sbx_test"
    assert (request.vcpus, request.mem_mib, request.disk_mib) == (2, 1024, 1024)
    assert updated == ResourcesUpdate(
        vcpus=ResourceOutcome(change="next_boot", previous=1, value=2),
        memory_mib=ResourceOutcome(change="refused", previous=512, value=512, reason="no"),
        disk_mib=ResourceOutcome(change="offline", previous=2048, value=1024),
        filesystem_bytes=1 << 30,
    )
    assert sandbox.disk_mib == 1024


def test_a_field_not_asked_for_is_absent_on_the_wire_and_in_the_answer(transport, sandbox):
    calls = answering(
        transport,
        api_pb2.UpdateResourcesResponse(
            disk_mib=api_pb2.ResourceOutcome(
                change=api_pb2.RESOURCE_CHANGE_LIVE, previous=1024, value=2048
            )
        ),
    )
    updated = sandbox.update_resources(disk_mib=2048)
    assert not calls[0][1].HasField("vcpus")
    assert updated.disk_mib.change == "live" and updated.vcpus is None


@pytest.mark.parametrize(
    "bad", [{"disk_mib": 0}, {"vcpus": -1}, {"memory_mib": 1.5}, {"vcpus": True}]
)
def test_a_value_that_is_not_a_positive_integer_is_refused_before_the_call(
    transport, sandbox, bad
):
    calls = answering(transport, api_pb2.UpdateResourcesResponse())
    with pytest.raises(BurrowError):
        sandbox.update_resources(**bad)
    assert calls == []


def test_a_lifetime_update_sends_only_what_it_was_given(transport, sandbox):
    calls = answering(transport, common_pb2.Sandbox(id="sbx_test"))
    sandbox.update_lifetime(max_lifetime_secs=7200, snapshot_keep_last=2)
    method, request = calls[0]
    assert method == "UpdateLifetime"
    assert request.max_lifetime_secs == 7200 and request.snapshot_keep_last == 2
    assert not request.HasField("idle_suspend_secs")
    assert not request.HasField("snapshot_expiration_secs")
