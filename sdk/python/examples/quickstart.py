# End-to-end tour of the SDK. Needs a running burrow stack:
#   docker --context colima-burrow compose -f deploy/dev/compose.yaml up -d
#
#   python examples/quickstart.py
import os
import shutil
import tempfile
import time

from burrow import Sandbox

# get_or_create keys on the sandbox's name, so running this twice reuses the
# first one. No network unless asked for: this one needs pypi, and nothing else.
sandbox = Sandbox.get_or_create(
    name=f"quickstart-py-{os.environ.get('USER', 'local').lower()}",
    # A create must name a template; burrow ships none of its own. Import this
    # one with: burrow pull python:3.12 --name python
    template="python",
    network_policy={
        "mode": "allowlist",
        "allow_domains": ["pypi.org", "*.pythonhosted.org"],
        "deny_cidrs": ["169.254.0.0/16"],
    },
    resources={"vcpus": 1, "memory_mib": 512, "idle_suspend_secs": 300, "suspended_ttl_secs": 3600},
    tags={"purpose": "quickstart", "owner": "sdk-example"},
    # Merged under every command this handle runs.
    env={"QUICKSTART": "1"},
    on_create=lambda s: print("created:", s.id),
    on_resume=lambda s: print("resumed:", s.name),
)
print("sandbox:", sandbox.name, sandbox.id, sandbox.state, f"{sandbox.vcpus} vcpu", f"{sandbox.memory_mib} MiB")

# The sandbox's own `subprocess`, `os`, `shutil`, `open` and `Path`: the
# stdlib's names and semantics, acting on the guest.
sp = sandbox.subprocess

try:
    # A list is passed to execve as it is.
    hello = sp.run(["echo", "hello from the sandbox"], capture_output=True, text=True)
    print("run:", hello.returncode, hello.stdout.strip())

    # shell=True goes through /bin/sh, so pipes and redirection work.
    piped = sp.check_output("echo one two three | tr ' ' '\\n' | wc -l", shell=True, text=True)
    print("shell:", piped.strip())

    # cwd and env as the stdlib takes them; env is laid over the guest's.
    where = sp.check_output("pwd; echo $QUICKSTART $STAGE", shell=True, text=True, cwd="/work", env={"STAGE": "tour"})
    print("cwd and env:", " | ".join(where.strip().split("\n")))

    # Popen streams; the command also has a cmd_id that get_command reattaches to.
    with sp.Popen("for i in 1 2 3; do echo tick $i; done", shell=True, stdout=sp.PIPE, text=True) as job:
        for line in job.stdout:
            print(f"  {line}", end="")

    sleeper = sp.Popen(["sleep", "60"])
    sleeper.kill()
    print("killed:", sleeper.wait())  # -9, as POSIX Popen reports a signal

    # Files, the stdlib way.
    sandbox.os.makedirs("/work", exist_ok=True)
    with sandbox.open("/work/hello.sh", "w") as f:
        f.write("echo written from the SDK\n")
    run = sandbox.Path("/work/run.sh")
    run.write_text("sh /work/hello.sh\n")
    run.chmod(0o755)
    print("file:", sp.check_output(["sh", "/work/run.sh"], text=True).strip())
    print("dir:", ", ".join(sorted(sandbox.os.listdir("/work"))))
    print("size:", sandbox.os.path.getsize("/work/hello.sh"))

    # Copy one back out to the local filesystem.
    local = os.path.join(tempfile.gettempdir(), "burrow-quickstart", "hello.sh")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    with sandbox.open("/work/hello.sh", "rb") as src, open(local, "wb") as dst:
        shutil.copyfileobj(src, dst)
    print("downloaded to:", local)

    # Denied hosts fail rather than silently succeeding.
    blocked = sp.run("wget -qO- http://example.com/", shell=True, capture_output=True)
    print("example.com reachable:", blocked.returncode == 0)

    # Tighten the policy on a running sandbox.
    sandbox.update_tags({"purpose": "quickstart", "stage": "locked-down"})
    sandbox.update_network_policy("none")
    print("tags now:", sandbox.tags)

    try:
        sp.run("exit 3", shell=True, check=True)
    except sp.CalledProcessError as err:
        print("caught exit:", err.returncode)

    try:
        sandbox.os.stat("/work/missing")
    except FileNotFoundError as err:
        print("missing:", err.filename)

    # Fork clones the sandbox's current state into a new one; the source's
    # state is written first, so the child starts from what it looks like right
    # now.
    child = sandbox.fork(name=f"{sandbox.name}-fork")
    try:
        print("fork:", child.name, child.id)
        print("fork sees the file:", child.Path("/work/hello.sh").read_text().strip())
    finally:
        child.delete()

    # stop suspends; resume brings it back.
    sandbox.stop()
    started = time.monotonic()
    sandbox.resume()
    print("resumed in:", f"{(time.monotonic() - started) * 1000:.0f}ms")
    print("file survived:", sandbox.Path("/work/hello.sh").read_text().strip())

    # Auto-resume: a call on a suspended sandbox resumes it and retries once.
    sandbox.stop()
    revived = sp.check_output(["cat", "/work/hello.sh"], text=True)
    print("auto-resumed:", revived.strip())
finally:
    sandbox.delete()
