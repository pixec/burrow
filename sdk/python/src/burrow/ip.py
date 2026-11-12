"""Dedicated public IPs: allocated from pools, attached to sandboxes, kept
until released and quarantined after."""

from __future__ import annotations

from typing import Any, List

from ._pb import api_pb2, common_pb2
from ._policy import as_section
from ._transport import Transport
from ._wire import at, at_or_none, label
from .types import IpPool, PublicIp


def to_public_ip(raw: common_pb2.PublicIp) -> PublicIp:
    return PublicIp(
        address=raw.address,
        family=raw.family,
        prefix_len=raw.prefix_len,
        pool=raw.pool,
        state=label(common_pb2.PublicIpState, raw.state, "PUBLIC_IP_STATE_") or "unknown",
        sandbox_id=raw.sandbox_id,
        node_id=raw.node_id,
        allocated_at=at(raw.allocated_at_unix_ms),
        attached_at=at_or_none(raw.attached_at_unix_ms),
        quarantined_until=at_or_none(raw.quarantined_until_unix_ms),
    )


def to_pool(pool: Any) -> common_pb2.IpPool:
    """Builds the wire `IpPool` from an `IpPool` or a dict of its fields."""
    pool = as_section(IpPool, "ip pool", pool)
    return common_pb2.IpPool(
        name=pool.name,
        node_id=pool.node_id,
        node_labels=pool.node_labels,
        ranges=pool.ranges,
        addresses=pool.addresses,
        gateway=pool.gateway,
        prefix_len=pool.prefix_len,
        nameservers=pool.nameservers,
        prefix6=pool.prefix6,
        per_sandbox=pool.per_sandbox,
        is_on_link=pool.on_link,
        is_smtp_allowed=pool.allow_smtp,
        is_wake_on_traffic=pool.wake_on_traffic,
        quarantine_secs=pool.quarantine_secs,
    )


def from_pool(raw: common_pb2.IpPool) -> IpPool:
    return IpPool(
        name=raw.name,
        node_id=raw.node_id,
        node_labels=dict(raw.node_labels),
        ranges=list(raw.ranges),
        addresses=list(raw.addresses),
        gateway=raw.gateway,
        prefix_len=raw.prefix_len,
        nameservers=list(raw.nameservers),
        prefix6=raw.prefix6,
        per_sandbox=raw.per_sandbox,
        on_link=raw.is_on_link,
        allow_smtp=raw.is_smtp_allowed,
        wake_on_traffic=raw.is_wake_on_traffic,
        quarantine_secs=raw.quarantine_secs,
        total=raw.total,
        allocated=raw.allocated,
    )


class Ips:
    """`burrow.ips`: dedicated public IPs and their pools on one connection.

    ```python
    ip = burrow.ips.allocate(sandbox_id="api")
    ```

    An address is kept until released, whatever happens to the sandbox holding
    it, and a released one is quarantined before anyone gets it again. It
    reaches one node, so a sandbox holding one cannot move.
    """

    def __init__(self, transport: Transport):
        self._transport = transport

    def allocate(self, *, pool: str = "", family: int = 4, sandbox_id: str = "") -> PublicIp:
        """Takes an address within this credential's quota. With `sandbox_id`,
        one reaching that sandbox's node, attached there."""
        return to_public_ip(
            self._transport.unary(
                "AllocateIp",
                api_pb2.AllocateIpRequest(pool=pool, family=family, sandbox_id=sandbox_id),
            )
        )

    def release(self, address: str) -> None:
        self._transport.unary("ReleaseIp", api_pb2.IpRef(address=address))

    def attach(self, address: str, sandbox_id: str) -> PublicIp:
        """Routes an address to a sandbox, by id or name."""
        return to_public_ip(
            self._transport.unary(
                "AttachIp", api_pb2.AttachIpRequest(address=address, sandbox_id=sandbox_id)
            )
        )

    def detach(self, address: str) -> PublicIp:
        """Takes an address off its sandbox, keeping it allocated."""
        return to_public_ip(self._transport.unary("DetachIp", api_pb2.IpRef(address=address)))

    def list(
        self, *, pool: str = "", sandbox_id: str = "", quarantined: bool = False
    ) -> List[PublicIp]:
        """The addresses this credential holds; an operator sees all."""
        res = self._transport.unary(
            "ListIps",
            api_pb2.ListIpsRequest(
                pool=pool, sandbox_id=sandbox_id, is_quarantine_included=quarantined
            ),
        )
        return [to_public_ip(ip) for ip in res.ips]

    def create_pool(self, pool: Any) -> IpPool:
        """Operator credentials only, as are the other pool calls."""
        return from_pool(self._transport.unary("CreateIpPool", to_pool(pool)))

    def update_pool(self, pool: Any) -> IpPool:
        """Replaces a pool's definition; its allocated addresses must stay in it."""
        return from_pool(self._transport.unary("UpdateIpPool", to_pool(pool)))

    def delete_pool(self, name: str) -> None:
        self._transport.unary("DeleteIpPool", api_pb2.IpPoolRef(name=name))

    def list_pools(self) -> List[IpPool]:
        res = self._transport.unary("ListIpPools", api_pb2.ListIpPoolsRequest())
        return [from_pool(pool) for pool in res.pools]
