# burrow-guest

The guest agent for [Burrow](https://github.com/pixec/burrow), running inside every sandbox to execute commands, transfer files and manage accounts on behalf of the node.

The agent serves the `Guest` gRPC service over vsock and accepts connections only from the host.
One binary covers Linux, macOS and Windows guests, and the node upgrades it in place when a sandbox runs an older build.

> [!NOTE]
> The agent is installed and upgraded by Burrow. You only need this crate to build Burrow from source or to work on the macOS and Windows template scripts.

## Platforms

| Guest | Runs as | Installed by |
| --- | --- | --- |
| Linux | PID 1, with the image's systemd as its child in systemd templates | the node, at template import |
| macOS | the LaunchDaemon `dev.burrow.guest` | the macOS template build, in `scripts/macos` |
| Windows | the LocalSystem service `burrow-guest` | the Windows template build, in `scripts/windows` |

## Building

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl -p burrow-guest
cargo zigbuild --release --target aarch64-unknown-linux-musl -p burrow-guest
cargo zigbuild --release --target x86_64-pc-windows-gnullvm -p burrow-guest
cargo build --release -p burrow-guest   # the macOS agent, on a Mac
```

## Testing

```sh
cargo test -p burrow-guest
```

The platform-independent tests run on every host. On Linux and macOS, the file operation tests also run against the host's own filesystem.
`examples/guest_probe.rs` exercises a running agent end to end through its vsock socket.

## Windows templates

[scripts/windows](../../scripts/windows/README.md) builds a Windows template unattended, with the virtio-win drivers and the agent installed as a service.

The service logs to `%ProgramData%\burrow\burrow-guest.log`. Set the machine environment variable `BURROW_SH` to a POSIX shell to run `sh -c` commands under it instead of `cmd.exe`.

> [!IMPORTANT]
> Firefox and Java keep their own certificate stores. In inspected sandboxes, enable Firefox's `ImportEnterpriseRoots` policy, and import the inspection root into Java's `cacerts` or run Java with `-Djavax.net.ssl.trustStoreType=Windows-ROOT`.

## macOS templates

Template builds install the agent over SSH, as described in [scripts/macos](../../scripts/macos/README.md).
A changed inspection root takes effect at the sandbox's next cold boot.

## Documentation

How the agent works inside a sandbox is documented at [burrow.pixec.net](https://burrow.pixec.net/internals/guest).
