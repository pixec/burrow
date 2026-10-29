//! Frames the stack answers itself, outside smoltcp: ARP, DHCP, ICMP echo,
//! and UDP, which is relayed per datagram rather than through sockets.

use std::net::Ipv4Addr;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, DhcpMessageType, DhcpOption, DhcpPacket, DhcpRepr,
    ETHERNET_HEADER_LEN, EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv4Packet,
    Icmpv4Repr, IpProtocol, Ipv4Packet, UdpPacket, UdpRepr,
};

use super::SandboxNet;

/// The gateway's MAC. Every sandbox has a link of its own, so one constant
/// serves them all; locally administered, unicast.
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0xb0, 0x77, 0x00, 0x00, 0x01];

const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;

/// Long enough that a guest renews rarely, short enough that a stale lease
/// does not outlive a sandbox for long. The address never changes anyway.
const LEASE_SECS: u32 = 24 * 60 * 60;

/// An Ethernet frame from the gateway to the guest around `payload`.
pub fn ethernet(net: &SandboxNet, ethertype: EthernetProtocol, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
    let mut eth = EthernetFrame::new_unchecked(&mut frame);
    eth.set_dst_addr(EthernetAddress(net.mac));
    eth.set_src_addr(EthernetAddress(GATEWAY_MAC));
    eth.set_ethertype(ethertype);
    eth.payload_mut().copy_from_slice(payload);
    frame
}

/// The reply to a guest's ARP request, when it asks for one of `owned`.
pub fn arp_reply(net: &SandboxNet, request: &[u8], owned: &[Ipv4Addr]) -> Option<Vec<u8>> {
    let packet = ArpPacket::new_checked(request).ok()?;
    let ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr,
        source_protocol_addr,
        target_protocol_addr,
        ..
    } = ArpRepr::parse(&packet).ok()?
    else {
        return None;
    };
    // Answering for the guest's own address, a gratuitous announcement or a
    // conflict probe, would tell it the address is taken.
    if source_hardware_addr.0 != net.mac || !owned.contains(&target_protocol_addr) {
        return None;
    }
    let reply = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: EthernetAddress(GATEWAY_MAC),
        source_protocol_addr: target_protocol_addr,
        target_hardware_addr: source_hardware_addr,
        target_protocol_addr: source_protocol_addr,
    };
    let mut body = vec![0u8; reply.buffer_len()];
    reply.emit(&mut ArpPacket::new_unchecked(&mut body));
    Some(ethernet(net, EthernetProtocol::Arp, &body))
}

/// IPv4 packets carrying `payload` from `src` to `dst`, fragmented to the
/// link's MTU.
///
/// Only UDP needs this: a resolver answer can be far larger than one frame,
/// and the guest reassembles. TCP segments come out of smoltcp sized already.
pub fn ipv4_packets(
    net: &SandboxNet,
    ident: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpProtocol,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let room = (usize::from(net.mtu) - IPV4_HEADER) & !7;
    let mut packets = Vec::new();
    let mut offset = 0;
    loop {
        let end = (offset + room).min(payload.len());
        let is_last = end == payload.len();
        let mut buf = vec![0u8; IPV4_HEADER + end - offset];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf);
        ip.set_version(4);
        ip.set_header_len(IPV4_HEADER as u8);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_len((IPV4_HEADER + end - offset) as u16);
        ip.set_ident(ident);
        ip.set_dont_frag(false);
        ip.set_more_frags(!is_last);
        ip.set_frag_offset(offset as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(protocol);
        ip.set_src_addr(src);
        ip.set_dst_addr(dst);
        ip.payload_mut().copy_from_slice(&payload[offset..end]);
        ip.fill_checksum();
        packets.push(ethernet(net, EthernetProtocol::Ipv4, &buf));
        if is_last {
            return packets;
        }
        offset = end;
    }
}

/// A UDP datagram to the guest, as however many frames it takes.
pub fn udp(
    net: &SandboxNet,
    ident: u16,
    (src, src_port): (Ipv4Addr, u16),
    (dst, dst_port): (Ipv4Addr, u16),
    data: &[u8],
) -> Vec<Vec<u8>> {
    let repr = UdpRepr { src_port, dst_port };
    let mut datagram = vec![0u8; UDP_HEADER + data.len()];
    repr.emit(
        &mut UdpPacket::new_unchecked(&mut datagram),
        &src.into(),
        &dst.into(),
        data.len(),
        |payload| payload.copy_from_slice(data),
        &ChecksumCapabilities::default(),
    );
    ipv4_packets(net, ident, src, dst, IpProtocol::Udp, &datagram)
}

/// The reply to an ICMP echo request addressed to the gateway.
pub fn echo_reply(net: &SandboxNet, ident: u16, ip: &Ipv4Packet<&[u8]>) -> Option<Vec<u8>> {
    let checksum = ChecksumCapabilities::default();
    let request = Icmpv4Packet::new_checked(ip.payload()).ok()?;
    let Icmpv4Repr::EchoRequest {
        ident: echo,
        seq_no,
        data,
    } = Icmpv4Repr::parse(&request, &checksum).ok()?
    else {
        return None;
    };
    let reply = Icmpv4Repr::EchoReply {
        ident: echo,
        seq_no,
        data,
    };
    let mut body = vec![0u8; reply.buffer_len()];
    reply.emit(&mut Icmpv4Packet::new_unchecked(&mut body[..]), &checksum);
    ipv4_packets(
        net,
        ident,
        ip.dst_addr(),
        ip.src_addr(),
        IpProtocol::Icmp,
        &body,
    )
    .pop()
}

/// The server's answer to one DHCP message from the guest.
///
/// There is exactly one address to give and one client to give it to, so
/// this is the whole server: every DISCOVER is offered the sandbox's address,
/// every REQUEST for it is acknowledged, and a REQUEST for any other address
/// is refused so a guest carrying a lease from somewhere else lets go of it.
pub fn dhcp_reply(net: &SandboxNet, ident: u16, message: &[u8]) -> Option<Vec<Vec<u8>>> {
    let packet = DhcpPacket::new_checked(message).ok()?;
    let request = DhcpRepr::parse(&packet).ok()?;
    if request.client_hardware_address.0 != net.mac {
        return None;
    }
    let message_type = match request.message_type {
        DhcpMessageType::Discover => DhcpMessageType::Offer,
        DhcpMessageType::Request => {
            let asked = request.requested_ip.unwrap_or(request.client_ip);
            if asked == net.guest_ip {
                DhcpMessageType::Ack
            } else {
                DhcpMessageType::Nak
            }
        }
        // An INFORM is a client with an address asking only for options.
        DhcpMessageType::Inform => DhcpMessageType::Ack,
        _ => return None,
    };
    let is_nak = message_type == DhcpMessageType::Nak;
    let is_inform = request.message_type == DhcpMessageType::Inform;

    let dns = net.dns_ip.octets();
    let mtu = net.mtu.to_be_bytes();
    let options = [
        DhcpOption {
            kind: 6,
            data: &dns,
        },
        DhcpOption {
            kind: 26,
            data: &mtu,
        },
    ];
    let mask = Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(net.prefix))
            .unwrap_or(0),
    );
    let reply = DhcpRepr {
        message_type,
        transaction_id: request.transaction_id,
        secs: 0,
        client_hardware_address: request.client_hardware_address,
        client_ip: if is_inform {
            request.client_ip
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        your_ip: if is_nak || is_inform {
            Ipv4Addr::UNSPECIFIED
        } else {
            net.guest_ip
        },
        server_ip: Ipv4Addr::UNSPECIFIED,
        router: (!is_nak).then_some(net.gateway_ip),
        subnet_mask: (!is_nak).then_some(mask),
        relay_agent_ip: Ipv4Addr::UNSPECIFIED,
        broadcast: request.broadcast,
        requested_ip: None,
        client_identifier: None,
        server_identifier: Some(net.gateway_ip),
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: (!is_nak && !is_inform).then_some(LEASE_SECS),
        renew_duration: (!is_nak && !is_inform).then_some(LEASE_SECS / 2),
        rebind_duration: (!is_nak && !is_inform).then_some(LEASE_SECS / 8 * 7),
        additional_options: if is_nak { &[] } else { &options },
    };
    let mut body = vec![0u8; reply.buffer_len()];
    reply.emit(&mut DhcpPacket::new_unchecked(&mut body)).ok()?;

    // A client that already has an address is answered there; one that has
    // none yet, or asked for broadcast, on the broadcast address. The frame
    // goes to its MAC either way, since there is only the one.
    let to = if !request.client_ip.is_unspecified() {
        request.client_ip
    } else if request.broadcast || is_nak {
        Ipv4Addr::BROADCAST
    } else {
        net.guest_ip
    };
    Some(udp(net, ident, (net.gateway_ip, 67), (to, 68), &body))
}

/// Whether a DHCP message is a REQUEST the reply to which is an ACK, which is
/// the moment the guest holds its lease.
pub fn is_lease_ack(reply: &[u8]) -> bool {
    let Ok(eth) = EthernetFrame::new_checked(reply) else {
        return false;
    };
    let Ok(ip) = Ipv4Packet::new_checked(eth.payload()) else {
        return false;
    };
    let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
        return false;
    };
    DhcpPacket::new_checked(udp.payload())
        .ok()
        .and_then(|packet| {
            DhcpRepr::parse(&packet).ok().map(|repr| {
                repr.message_type == DhcpMessageType::Ack && !repr.your_ip.is_unspecified()
            })
        })
        .unwrap_or(false)
}
