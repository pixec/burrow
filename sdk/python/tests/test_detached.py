# A spawned command holds its request stream open so the guest keeps stdin
# open, and something has to let go of it. These check the handle does, without
# needing a sandbox: `DetachedCommand` is handed its callables by `_spawn`.

import pytest

from burrow.errors import BurrowError
from burrow.sandbox import DetachedCommand


def make(signal=lambda cmd_id, sig: None):
    """A handle over recording stand-ins for the two ways of letting go."""
    state = {"released": 0, "closed": 0}

    def release():
        state["released"] += 1

    def close():
        state["released"] += 1
        state["closed"] += 1

    handle = DetachedCommand(
        "sbx_test",
        "cmd_test",
        lambda: iter(()),
        signal,
        release=release,
        close=close,
    )
    return handle, state


def test_close_releases_the_request_side_and_cancels():
    handle, state = make()
    handle.close()
    assert state["released"] == 1
    assert state["closed"] == 1


def test_the_context_manager_closes_on_the_way_out():
    handle, state = make()
    with pytest.raises(ValueError):
        with handle as entered:
            assert entered is handle
            assert state["closed"] == 0
            raise ValueError("boom")
    assert state["closed"] == 1


def test_kill_releases_the_request_side_without_cancelling():
    # The output stays readable: the exit status of what was just killed is
    # the thing a caller most often wants next.
    handle, state = make()
    handle.kill()
    assert state["released"] == 1
    assert state["closed"] == 0


def test_kill_releases_even_when_the_signal_is_refused():
    def refuse(cmd_id, sig):
        raise BurrowError("exec is denied", "permission_denied")

    handle, state = make(signal=refuse)
    with pytest.raises(BurrowError):
        handle.kill()
    assert state["released"] == 1


def test_a_reattached_handle_owns_no_stream():
    # `get_command` hands back a handle with neither callable; nothing to
    # release, and calling close() anyway must not blow up.
    handle = DetachedCommand("sbx_test", "cmd_test", lambda: iter(()), lambda *_: None)
    handle.close()
    handle.kill()
