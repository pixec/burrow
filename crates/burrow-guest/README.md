# burrow-guest

The guest agent for [Burrow](https://github.com/pixec/burrow), running inside every sandbox to execute commands, transfer files and manage accounts on behalf of the node.

The agent serves the `Guest` gRPC service over vsock and accepts connections only from the host.
One binary covers Linux, macOS and Windows guests, and the node upgrades it in place when a sandbox runs an older build.

> [!NOTE]
> The agent is installed and upgraded by Burrow. You only need this crate to build Burrow from source or to prepare a macOS or Windows template by hand.

## Platforms

| Guest | Runs as | Installed by |
| --- | --- | --- |
| Linux | PID 1, with the image's systemd as its child in systemd templates | the node, at template import |
| macOS | the LaunchDaemon `dev.burrow.guest` | `burrow-guest install`, run during the template build |
| Windows | the LocalSystem service `burrow-guest` | `burrow-guest.exe install --start`, run once in the template |

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

1. Install the virtio-win drivers for storage (`viostor` or `vioscsi`), networking (`NetKVM`) and vsock (`viosock`, with its Winsock provider).
2. Copy `burrow-guest.exe` to a permanent location, such as `C:\Program Files\Burrow\`.
3. Run `burrow-guest.exe install --start`.
4. Optionally, set the machine environment variable `BURROW_SH` to a POSIX shell for `sh -c` commands. Without one, they run under `cmd.exe`.

The service logs to `%ProgramData%\burrow\burrow-guest.log`. Run `burrow-guest.exe console` to see logs in the foreground.

> [!IMPORTANT]
> Firefox and Java keep their own certificate stores. In inspected sandboxes, enable Firefox's `ImportEnterpriseRoots` policy, and import the inspection root into Java's `cacerts` or run Java with `-Djavax.net.ssl.trustStoreType=Windows-ROOT`.

## macOS templates

Template builds install the agent over SSH, as described in [deploy/macos](../../deploy/macos/README.md).
A changed inspection root takes effect at the sandbox's next cold boot.

## Documentation

How the agent works inside a sandbox is documented at [burrow.pixec.net](https://burrow.pixec.net/internals/guest).
