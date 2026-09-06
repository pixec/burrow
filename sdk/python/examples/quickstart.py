# End-to-end tour of the SDK. Needs a running burrow stack:
#   docker --context colima-burrow compose -f deploy/dev/compose.yaml up -d
#
#   python examples/quickstart.py
import os
import tempfile

from burrow import CommandFailedError, Sandbox

# get_or_create keys on the sandbox's name, so running this twice reuses the
# first one. No network unless asked for: this one needs pypi, and nothing else.
sandbox = Sandbox.get_or_create(
    name=f"quickstart-py-{os.environ.get('USER', 'local').lower()}",
    # A create must name a template; burrow ships none of its own. Import this
    # one with: burrow pull python:3.12 --name python
    template="python",
    # The shorthand policy shape. `subnets` maps to allowed and denied ranges.
    network_policy={
        "allow": ["pypi.org", "*.pythonhosted.org"],
        "subnets": {"deny": ["169.254.0.0/16"]},
    },
    resources={"vcpus": 1, "memory_mib": 512, "idle_suspend_secs": 300, "suspended_ttl_secs": 3600},
    tags={"purpose": "quickstart", "owner": "sdk-example"},
    # Merged under every command this handle runs.
    env={"QUICKSTART": "1"},
    on_create=lambda s: print("created:", s.id),
    on_resume=lambda s: print("resumed:", s.name),
)
print("sandbox:", sandbox.name, sandbox.id, sandbox.status, f"{sandbox.vcpus} vcpu", f"{sandbox.memory} MiB")

try:
    # run_command runs to completion.
    hello = sandbox.run_command("echo", ["hello from the sandbox"])
    print("run:", hello.exit_code, hello.stdout.strip())

    # A bare string goes through a shell, so pipes and redirection work.
    piped = sandbox.run_command("echo one two three | tr ' ' '\\n' | wc -l")
    print("shell:", piped.stdout.strip())

    # Keyword options carry cwd and env.
    where = sandbox.run_command(
        "sh", ["-c", "pwd; echo $QUICKSTART $STAGE"], cwd="/work", env={"STAGE": "tour"}
    )
    print("cwd and env:", " | ".join(where.stdout.strip().split("\n")))

    # Detached hands back a handle you can stream from, wait on, or kill.
    job = sandbox.run_command("sh", ["-c", "for i in 1 2 3; do echo tick $i; done"], detached=True)
    for chunk in job.logs():
        if chunk.type == "stdout":
            print(f"  {chunk.data}", end="")

    sleeper = sandbox.run_command("sleep", ["60"], detached=True)
    sleeper.kill()
    print("killed:", sleeper.wait().exit_code)

    # Write several files in one call.
    sandbox.write_files([
        {"path": "/work/hello.sh", "content": "echo written from the SDK\n"},
        {"path": "/work/run.sh", "content": "sh /work/hello.sh\n", "mode": 0o755},
    ])
    script = sandbox.run_command("sh", ["/work/run.sh"])
    print("file:", script.stdout.strip())
    print("dir:", ", ".join(entry.name for entry in sandbox.list_dir("/work")))

    # Copy one back out to the local filesystem.
    copied = sandbox.download_file(
        "/work/hello.sh", f"{tempfile.gettempdir()}/burrow-quickstart/hello.sh"
    )
    print("downloaded to:", copied)

    # Denied hosts fail rather than silently succeeding.
    blocked = sandbox.run_command("wget -qO- http://example.com/")
    print("example.com reachable:", blocked.exit_code == 0)

    # Tighten the policy on a running sandbox. Tags and network in one call.
    sandbox.update(
        tags={"purpose": "quickstart", "stage": "locked-down"},
        network_policy="deny-all",
    )
    print("tags now:", sandbox.tags)

    try:
        sandbox.exec("exit 3", check=True)
    except CommandFailedError as err:
        print("caught exit:", err.exit_code)

    # Fork clones the sandbox's current state into a new one; the source's
    # state is written first, so the child starts from what it looks like right
    # now.
    child = sandbox.fork(name=f"{sandbox.name}-fork")
    try:
        print("fork:", child.name, child.id)
        print("fork sees the file:", child.read_file("/work/hello.sh").strip())
    finally:
        child.delete()

    # stop suspends; resume brings it back.
    sandbox.stop()
    import time

    started = time.monotonic()
    sandbox.resume()
    print("resumed in:", f"{(time.monotonic() - started) * 1000:.0f}ms")
    print("file survived:", sandbox.read_file("/work/hello.sh").strip())

    # Auto-resume: a call on a suspended sandbox resumes it and retries once.
    sandbox.stop()
    revived = sandbox.run_command("cat", ["/work/hello.sh"])
    print("auto-resumed:", revived.stdout.strip())
finally:
    sandbox.delete()
