# `sandbox.subprocess` over the scripted programs in conftest.py.

import subprocess

import pytest

from burrow._pb import api_pb2
from conftest import err, exit_code, out


def test_the_stdlib_names_are_the_stdlibs_own(sandbox):
    sp = sandbox.subprocess
    assert (sp.PIPE, sp.STDOUT, sp.DEVNULL) == (
        subprocess.PIPE,
        subprocess.STDOUT,
        subprocess.DEVNULL,
    )
    assert sp.CalledProcessError is subprocess.CalledProcessError
    assert sp.TimeoutExpired is subprocess.TimeoutExpired
    assert sp.CompletedProcess is subprocess.CompletedProcess


def test_argv_with_and_without_a_shell(sandbox, transport):
    transport.programs["ls -l"] = lambda guest: iter([exit_code(0)])
    transport.programs["/bin/sh"] = lambda guest: iter([exit_code(0)])
    sandbox.subprocess.run("ls -l")
    sandbox.subprocess.run("ls -l", shell=True)
    sandbox.subprocess.run(["echo hi", "x"], shell=True)
    sandbox.subprocess.run(["echo", "a b"], stdout=subprocess.DEVNULL)
    assert [list(s.cmd) for s in transport.started] == [
        ["ls -l"],
        ["/bin/sh", "-c", "ls -l"],
        ["/bin/sh", "-c", "echo hi", "x"],
        ["echo", "a b"],
    ]


def test_run_captures_bytes_or_text(sandbox, transport):
    def both(guest):
        yield out(b"to out\r\n")
        yield err(b"to err\n")
        yield exit_code(0)

    transport.programs["both"] = both
    result = sandbox.subprocess.run(["both"], capture_output=True)
    assert isinstance(result, subprocess.CompletedProcess)
    assert (result.returncode, result.stdout, result.stderr) == (0, b"to out\r\n", b"to err\n")
    assert result.args == ["both"]
    text = sandbox.subprocess.run(["both"], capture_output=True, text=True)
    assert (text.stdout, text.stderr) == ("to out\n", "to err\n")
    merged = sandbox.subprocess.run(["both"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert merged.stdout == b"to out\r\nto err\n" and merged.stderr is None


def test_run_passes_cwd_env_and_user(sandbox, transport):
    sandbox._env = {"BASE": "1", "STAGE": "handle"}
    sandbox.as_user("alice").subprocess.run(
        ["echo"], cwd="/work", env={"STAGE": "call"}, stdout=subprocess.DEVNULL
    )
    start = transport.started[-1]
    assert (start.cwd, start.user) == ("/work", "alice")
    assert dict(start.env) == {"BASE": "1", "STAGE": "call"}


def test_check_raises_the_stdlib_error(sandbox, transport):
    def fail(guest):
        yield out(b"partial")
        yield err(b"boom")
        yield exit_code(3)

    transport.programs["fail"] = fail
    assert sandbox.subprocess.run(["fail"], capture_output=True).returncode == 3
    with pytest.raises(subprocess.CalledProcessError) as caught:
        sandbox.subprocess.run(["fail"], capture_output=True, check=True)
    assert caught.value.returncode == 3
    assert (caught.value.stdout, caught.value.stderr) == (b"partial", b"boom")
    with pytest.raises(subprocess.CalledProcessError):
        sandbox.subprocess.check_call(["fail"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert sandbox.subprocess.check_output(["echo", "hi"], text=True) == "hi\n"
    assert sandbox.subprocess.call(["fail"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 3


def test_getstatusoutput(sandbox, transport):
    def shell(guest):
        yield out(b"merged\n")
        yield exit_code(2)

    transport.programs["/bin/sh"] = shell
    assert sandbox.subprocess.getstatusoutput("whatever") == (2, "merged")
    assert sandbox.subprocess.getoutput("whatever") == "merged"


def test_a_timeout_kills_and_keeps_the_output(sandbox, transport):
    def slow(guest):
        yield out(b"started\n")
        guest.signalled.wait(10)
        yield api_pb2.ExecOutput(exit_signal=guest.signal)
        yield exit_code(128 + guest.signal)

    transport.programs["slow"] = slow
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        sandbox.subprocess.run(["slow"], capture_output=True, timeout=0.2)
    assert caught.value.timeout == 0.2
    assert caught.value.stdout == b"started\n"
    assert transport.signals == [("cmd_1", 9)]


def test_input_goes_to_stdin(sandbox):
    result = sandbox.subprocess.run(["cat"], input="héllo", capture_output=True, text=True)
    assert result.stdout == "héllo"
    with pytest.raises(ValueError):
        sandbox.subprocess.run(["cat"], input=b"x", stdin=subprocess.PIPE)


def test_popen_pipes(sandbox):
    with sandbox.subprocess.Popen(
        ["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    ) as proc:
        assert proc.pid is None and proc.cmd_id == "cmd_1"
        proc.stdin.write("one\ntwo\n")
        proc.stdin.flush()
        assert proc.stdout.readline() == "one\n"
        assert proc.poll() is None
        proc.stdin.close()
        assert proc.stdout.read() == "two\n"
    assert proc.returncode == 0


def test_communicate(sandbox):
    proc = sandbox.subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert proc.communicate(b"data") == (b"data", None)
    assert proc.returncode == 0
    with pytest.raises(ValueError):
        proc.communicate(b"more")


def test_communicate_timeout_loses_nothing(sandbox, transport):
    proc = sandbox.subprocess.Popen(["sleep"], stdout=subprocess.PIPE)
    with pytest.raises(subprocess.TimeoutExpired):
        proc.communicate(timeout=0.1)
    with pytest.raises(subprocess.TimeoutExpired):
        proc.wait(timeout=0.05)
    proc.terminate()
    assert proc.communicate() == (b"", None)
    assert proc.returncode == -15


def test_a_signal_exit_is_minus_the_signal(sandbox, transport):
    proc = sandbox.subprocess.Popen(["sleep"])
    proc.kill()
    assert proc.wait() == -9
    assert transport.signals == [("cmd_1", 9)]
    # Signalling what has exited does nothing, as the stdlib does.
    proc.kill()
    assert len(transport.signals) == 1


def test_a_stdlib_signal_crosses_by_name(sandbox, transport):
    import signal

    proc = sandbox.subprocess.Popen(["sleep"])
    proc.send_signal(signal.SIGUSR1)
    # SIGUSR1 is 10 on Linux, whatever this machine numbers it.
    assert transport.signals[-1][1] == 10
    assert proc.wait() == -signal.SIGUSR1


def test_inherited_output_goes_to_this_processes_descriptors(sandbox, capfd):
    sandbox.subprocess.run(["echo", "inherited"])
    assert capfd.readouterr().out == "inherited\n"


def test_get_command_replays_then_follows(sandbox, transport):
    def attach(start, guest):
        assert (start.command_id, start.from_offset) == ("cmd_9", 3)
        yield out(b"replayed\n")
        for data in guest.stdin():
            yield out(data)
        yield exit_code(0)

    transport.attach = attach
    shell = sandbox.get_command("cmd_9", from_offset=3)
    assert shell.cmd_id == "cmd_9" and shell.args == ["/bin/sh"]
    assert shell.stdout.readline() == b"replayed\n"
    shell.stdin.write(b"typed\n")
    shell.stdin.flush()
    assert shell.stdout.readline() == b"typed\n"
    shell.stdin.close()
    assert shell.wait() == 0


def test_leaving_an_attached_command_does_not_end_it(sandbox, transport):
    def attach(start, guest):
        guest.signalled.wait(10)
        yield exit_code(0)

    transport.attach = attach
    with sandbox.get_command("cmd_9") as shell:
        shell.stdin.write(b"x")
    # The program never reads its requests, so everything sent is still queued.
    sent = [msg.WhichOneof("input") for msg in list(shell._inputs.queue) if msg is not None]
    assert sent == ["stdin"]
    assert shell._call.cancelled()
