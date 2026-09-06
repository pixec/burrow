# Tags

Sandboxes carry key-value tags for categorization: environment, team, task,
whatever your scheme needs. Tags are the `metadata` map on the sandbox record.
You set them at creation, replace them at any time, and filter on them when
listing.

A tag is not a name. Tags are many per sandbox, changeable, and shared by
design; a name is one per sandbox, unique across the fleet, fixed once the
sandbox exists, and usable in place of its id ([CONCEPTS.md](CONCEPTS.md)). Use
a name to address one sandbox, and tags to find a group of them.

## Set at creation

```sh
burrow create --template base --tag env=staging --tag team=infra
```

## Update

```sh
burrow config tags <id> --tag env=production
```

`UpdateTags` replaces the full tag set. Pass every tag you want to keep, and
passing none clears them.

## Filter

```sh
burrow ps --tag env=staging
```

`ListSandboxes` filters by one `key=value` pair at a time, matched exactly. The
key alone is not a match. The filter is answered from the orchestrator's own
registry, which already holds every sandbox in the fleet, rather than fanned out
to the nodes.

A forked sandbox inherits its source's tags.

## Limits

| Limit | Value |
| --- | --- |
| Tags per sandbox | 16 |
| Key length | 1-64 bytes |
| Value length | up to 256 bytes |
| Forbidden characters | control characters (below `0x20`, and `0x7F`) |

Limits are enforced on the orchestrator and again on the node, which is the tier
that writes the durable record. Tags are echoed back in every list and get, so a
value carrying a newline or an escape sequence would forge lines in the output
an operator reads as the system's own.
