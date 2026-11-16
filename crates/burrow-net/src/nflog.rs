//! Drops the sandbox chains log to NFLOG, read back over netlink.
//!
//! The parser is plain bytes in, records out, so it is tested everywhere; the
//! socket is Linux only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::firewall::Refusal;

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
#[cfg(target_os = "linux")]
const NFULNL_MSG_CONFIG: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const NFULA_IFINDEX_INDEV: u16 = 4;
const NFULA_IFINDEX_OUTDEV: u16 = 5;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
/// Bytes of each packet copied to the reader: an IPv6 header and the ports.
#[cfg(target_os = "linux")]
const COPY_RANGE: u32 = 64;

/// One drop the kernel logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drop {
    pub refusal: Refusal,
    /// Interface indexes the packet came in on and was going out of, 0 for
    /// none.
    pub indev: u32,
    pub outdev: u32,
    pub source: IpAddr,
    pub destination: IpAddr,
    /// `tcp`, `udp`, `icmp` or the protocol number.
    pub protocol: String,
    /// The destination port, 0 for a protocol without one.
    pub port: u16,
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Every drop in a buffer of netlink messages. A message that is not an
/// NFLOG packet with a prefix this node writes is skipped.
pub fn parse(mut buf: &[u8], out: &mut Vec<Drop>) {
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            return;
        }
        let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if kind == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET
            && let Some(drop) = parse_packet(&buf[NLMSG_HDRLEN..len])
        {
            out.push(drop);
        }
        buf = &buf[align(len).min(buf.len())..];
    }
}

fn parse_packet(message: &[u8]) -> Option<Drop> {
    let mut attrs = message.get(NFGENMSG_LEN..)?;
    let (mut prefix, mut indev, mut outdev, mut payload) = (None, 0, 0, None);
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes(attrs[0..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(attrs[2..4].try_into().unwrap()) & 0x3fff;
        if len < 4 || len > attrs.len() {
            break;
        }
        let value = &attrs[4..len];
        let be32 = || {
            value
                .get(..4)
                .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
        };
        match kind {
            NFULA_PREFIX => {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                prefix = std::str::from_utf8(&value[..end]).ok();
            }
            NFULA_IFINDEX_INDEV => indev = be32().unwrap_or(0),
            NFULA_IFINDEX_OUTDEV => outdev = be32().unwrap_or(0),
            NFULA_PAYLOAD => payload = Some(value),
            _ => {}
        }
        attrs = &attrs[align(len).min(attrs.len())..];
    }
    let refusal = Refusal::from_prefix(prefix?)?;
    let (source, destination, protocol, port) = parse_ip(payload?)?;
    Some(Drop {
        refusal,
        indev,
        outdev,
        source,
        destination,
        protocol,
        port,
    })
}

fn parse_ip(packet: &[u8]) -> Option<(IpAddr, IpAddr, String, u16)> {
    let (source, destination, protocol, transport) = match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet.first()? & 0x0f) * 4;
            let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(source)),
                IpAddr::V4(Ipv4Addr::from(destination)),
                *packet.get(9)?,
                packet.get(header..).unwrap_or_default(),
            )
        }
        6 => {
            let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            (
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
                *packet.get(6)?,
                packet.get(40..).unwrap_or_default(),
            )
        }
        _ => return None,
    };
    let (name, has_ports) = match protocol {
        6 => ("tcp".to_string(), true),
        17 => ("udp".to_string(), true),
        132 => ("sctp".to_string(), true),
        1 => ("icmp".to_string(), false),
        58 => ("icmpv6".to_string(), false),
        other => (other.to_string(), false),
    };
    let port = match (has_ports, transport.get(2..4)) {
        (true, Some(port)) => u16::from_be_bytes(port.try_into().unwrap()),
        _ => 0,
    };
    Some((source, destination, name, port))
}

/// A netlink socket bound to one NFLOG group.
#[cfg(target_os = "linux")]
pub struct Socket(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl Socket {
    /// Binds `group`, copying the head of every packet logged to it.
    pub fn open(group: u16) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        // SAFETY: plain socket calls on a descriptor this function owns, with
        // pointers to locals that outlive each call.
        let socket = unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            );
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let socket = Self(std::os::fd::OwnedFd::from_raw_fd(fd));
            let mut address: libc::sockaddr_nl = std::mem::zeroed();
            address.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                fd,
                (&raw const address).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let size: libc::c_int = 4 << 20;
            libc::setsockopt(
                socket.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as u32,
            );
            socket
        };
        // Command 1 binds the group.
        socket.configure(1, group, 1, &[1])?;
        let mut mode = COPY_RANGE.to_be_bytes().to_vec();
        // NFULNL_COPY_PACKET, then padding.
        mode.extend_from_slice(&[2, 0]);
        socket.configure(2, group, 2, &mode)?;
        Ok(socket)
    }

    /// Sends one config attribute for `group` as message `seq` and waits for
    /// its ack, passing over packets logged meanwhile.
    fn configure(&self, seq: u32, group: u16, attribute: u16, value: &[u8]) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let attr_len = 4 + value.len();
        let len = NLMSG_HDRLEN + NFGENMSG_LEN + align(attr_len);
        let mut message = Vec::with_capacity(len);
        message.extend_from_slice(&(len as u32).to_ne_bytes());
        message.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
        message.extend_from_slice(&group.to_be_bytes());
        message.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        message.extend_from_slice(&attribute.to_ne_bytes());
        message.extend_from_slice(value);
        message.resize(len, 0);
        // SAFETY: a send of a buffer that lives across the call.
        if unsafe { libc::send(self.0.as_raw_fd(), message.as_ptr().cast(), len, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let read = self.recv(&mut buf)?;
            match ack_for(&buf[..read], seq) {
                Some(0) => return Ok(()),
                Some(errno) => return Err(std::io::Error::from_raw_os_error(errno)),
                None => {}
            }
        }
    }

    /// Reads one batch of messages, blocking until there is one.
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd as _;
        // SAFETY: a recv into a buffer that lives across the call.
        let read = unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(read as usize)
    }
}

/// The errno the ack to message `seq` carries, 0 for success, or `None`
/// when `buf` holds no ack to it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ack_for(mut buf: &[u8], seq: u32) -> Option<i32> {
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            return None;
        }
        let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        let acked = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        if kind == NLMSG_ERROR && acked == seq && len >= NLMSG_HDRLEN + 4 {
            return Some(-i32::from_ne_bytes(
                buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap(),
            ));
        }
        buf = &buf[align(len).min(buf.len())..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(align(out.len()), 0);
        out
    }

    fn message(kind: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = attrs.concat();
        let len = NLMSG_HDRLEN + NFGENMSG_LEN + body.len();
        let mut out = (len as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(&[2, 0, 0x1b, 0xbd]);
        out.extend_from_slice(&body);
        out
    }

    fn ipv4_tcp(source: [u8; 4], destination: [u8; 4], port: u16) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(&40000u16.to_be_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet
    }

    #[test]
    fn a_logged_drop_is_read_with_its_refusal_interfaces_and_destination() {
        let packet = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET;
        let buf = [
            message(
                packet,
                &[
                    attr(NFULA_PREFIX, b"burrow:port\0"),
                    attr(NFULA_IFINDEX_INDEV, &7u32.to_be_bytes()),
                    attr(NFULA_PAYLOAD, &ipv4_tcp([10, 99, 0, 6], [192, 0, 2, 9], 25)),
                ],
            ),
            message(
                packet,
                &[
                    attr(NFULA_PREFIX, b"someone-else\0"),
                    attr(NFULA_PAYLOAD, &ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 80)),
                ],
            ),
            message(
                packet,
                &[
                    attr(NFULA_PREFIX, b"burrow:unmatched\0"),
                    attr(NFULA_IFINDEX_INDEV, &2u32.to_be_bytes()),
                    attr(NFULA_IFINDEX_OUTDEV, &7u32.to_be_bytes()),
                    attr(NFULA_PAYLOAD, &{
                        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
                        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
                        v6.extend_from_slice(&"fd99::2".parse::<Ipv6Addr>().unwrap().octets());
                        v6.extend_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
                        v6
                    }),
                ],
            ),
        ]
        .concat();
        let mut drops = Vec::new();
        parse(&buf, &mut drops);
        assert_eq!(
            drops,
            [
                Drop {
                    refusal: Refusal::Port,
                    indev: 7,
                    outdev: 0,
                    source: "10.99.0.6".parse().unwrap(),
                    destination: "192.0.2.9".parse().unwrap(),
                    protocol: "tcp".into(),
                    port: 25,
                },
                Drop {
                    refusal: Refusal::Unmatched,
                    indev: 2,
                    outdev: 7,
                    source: "2001:db8::1".parse().unwrap(),
                    destination: "fd99::2".parse().unwrap(),
                    protocol: "udp".into(),
                    port: 53,
                },
            ]
        );
    }

    #[test]
    fn truncated_messages_are_skipped_rather_than_read_past() {
        let packet = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET;
        let whole = message(
            packet,
            &[
                attr(NFULA_PREFIX, b"burrow:range\0"),
                attr(
                    NFULA_PAYLOAD,
                    &ipv4_tcp([10, 99, 0, 6], [192, 0, 2, 9], 443),
                ),
            ],
        );
        for cut in 0..whole.len() {
            let mut drops = Vec::new();
            parse(&whole[..cut], &mut drops);
            assert!(drops.is_empty());
        }
        let mut short_payload = Vec::new();
        parse(
            &message(
                packet,
                &[
                    attr(NFULA_PREFIX, b"burrow:range\0"),
                    attr(NFULA_PAYLOAD, &[0x45, 0, 0]),
                ],
            ),
            &mut short_payload,
        );
        assert!(short_payload.is_empty());
    }

    #[test]
    fn only_the_ack_to_the_message_sent_answers_it() {
        let ack = |seq: u32, errno: i32| {
            let mut ack = 36u32.to_ne_bytes().to_vec();
            ack.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
            ack.extend_from_slice(&[0; 2]);
            ack.extend_from_slice(&seq.to_ne_bytes());
            ack.extend_from_slice(&[0; 4]);
            ack.extend_from_slice(&(-errno).to_ne_bytes());
            ack.extend_from_slice(&[0; 16]);
            ack
        };
        let packet = message(
            (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET,
            &[attr(NFULA_PREFIX, b"burrow:range\0")],
        );
        assert_eq!(ack_for(&packet, 2), None);
        assert_eq!(ack_for(&[packet.clone(), ack(2, 16)].concat(), 2), Some(16));
        assert_eq!(ack_for(&ack(1, 0), 2), None);
        assert_eq!(ack_for(&ack(2, 0), 2), Some(0));
    }
}
