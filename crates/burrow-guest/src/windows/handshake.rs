//! The host's handshake, on Windows: clock, trust, network, volumes.
//!
//! Entropy: Windows has no call that credits outside entropy to the kernel's
//! RNG the way Linux's `RNDADDENTROPY` does; `BCryptGenRandom` takes no seed.
//! What reseeds a restored Windows guest is the VM Generation ID: Windows'
//! vmgenid driver sees the identifier change and reseeds the kernel RNG,
//! which needs a VMM that gives each restored process a new identifier;
//! Burrow's Cloud Hypervisor config adds no vmgenid device. The host's bytes
//! are accepted and not used, and `reseed_us` reports zero. A host that
//! restores without vmgenid leaves clones sharing RNG state, and that is the
//! host's to provide, not something the agent can repair.

#![allow(clippy::result_large_err)]

use std::sync::Mutex;

use tonic::Status;

use burrow_proto::guest::v1 as guestpb;

use crate::windows::{netcfg, vsock, win};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn handshake(
    arrival: Option<vsock::Arrival>,
    req: guestpb::HandshakeRequest,
) -> Result<guestpb::HandshakeResponse, Status> {
    tracing::debug!(restored = req.is_restored, "handshake from host");
    let started = std::time::Instant::now();
    let reseeded = started.elapsed();
    if let Err(err) = set_clock(req.host_time_unix_nanos) {
        tracing::error!(%err, "failed to set guest clock");
    }
    let clocked = started.elapsed();

    // Fatal, as on Linux: a sandbox told to trust a CA and unable to would
    // fail every HTTPS request through the inspecting proxy.
    let pem = req.inspection_ca_pem.clone();
    let bundles = req.extra_trust_bundles.clone();
    tokio::task::spawn_blocking(move || install_inspection_ca(&pem, &bundles))
        .await
        .map_err(|err| Status::internal(format!("trust install did not run: {err}")))?
        .map_err(|err| {
            tracing::error!(%err, "failed to install the inspection ca");
            Status::internal(format!("installing the inspection ca: {err}"))
        })?;
    let trusted = started.elapsed();

    // Applied on every handshake that carries one, cold boot included:
    // Windows has no kernel command line to have brought the address up
    // with. Fatal, as on Linux.
    if let Some(network) = req.network.filter(|network| !network.ip.is_empty()) {
        tokio::task::spawn_blocking(move || apply_network(&network))
            .await
            .map_err(|err| Status::internal(format!("network did not run: {err}")))?
            .map_err(|err| {
                tracing::error!(%err, "failed to apply network");
                Status::internal(format!("applying network: {err}"))
            })?;
    }

    // Fatal, as on Linux: a sandbox whose volume is missing would write to
    // the directory beneath instead.
    crate::windows::volumes::mount(&req.volumes).await?;

    let total = started.elapsed();
    let timing = guestpb::GuestResumeTiming {
        parked_us: arrival.map_or(0, |a| a.parked.as_micros() as u64),
        accept_to_call_us: arrival.map_or(0, |a| {
            a.accepted_at.elapsed().saturating_sub(total).as_micros() as u64
        }),
        reseed_us: reseeded.as_micros() as u64,
        clock_us: (clocked - reseeded).as_micros() as u64,
        trust_us: (trusted - clocked).as_micros() as u64,
        trust_write_us: (trusted - clocked).as_micros() as u64,
        network_us: (total - trusted).as_micros() as u64,
        total_us: total.as_micros() as u64,
        ..Default::default()
    };
    Ok(guestpb::HandshakeResponse {
        agent_version: VERSION.into(),
        timing: Some(timing),
        agent_digest: crate::windows::service::self_digest().to_string(),
    })
}

/// Sets the system clock from the host's. Needs SeSystemtimePrivilege,
/// which LocalSystem holds and the agent enables at start.
fn set_clock(unix_nanos: i64) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::SystemInformation::SetSystemTime;
    use windows_sys::Win32::System::Time::FileTimeToSystemTime;
    if unix_nanos <= 0 {
        return Ok(());
    }
    let ticks = crate::windows::mode::unix_ns_to_filetime(unix_nanos) as u64;
    let filetime = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut system: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: both structures are live locals.
    win::check(unsafe { FileTimeToSystemTime(&filetime, &mut system) })?;
    // SAFETY: as above.
    win::check(unsafe { SetSystemTime(&system) })?;
    tracing::debug!(unix_nanos, "guest clock synced to host");
    Ok(())
}

/// The certificates in a PEM bundle, as DER.
fn pem_certificates(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    use base64::Engine as _;
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            body = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            let text = body.take().unwrap_or_default();
            out.push(base64::engine::general_purpose::STANDARD.decode(text)?);
        } else if let Some(body) = &mut body {
            body.push_str(line);
        }
    }
    anyhow::ensure!(!out.is_empty(), "no certificate in the inspection ca");
    Ok(out)
}

/// What this process has already installed, so a repeated handshake has
/// nothing to do.
fn installed() -> &'static Mutex<Option<(String, Vec<guestpb::TrustBundle>)>> {
    static INSTALLED: Mutex<Option<(String, Vec<guestpb::TrustBundle>)>> = Mutex::new(None);
    &INSTALLED
}

/// Installs the CA a sandbox was told to trust: into the machine's Trusted
/// Root store, which Windows' own TLS stack (Schannel) and everything built
/// on it verify against; as a PEM file under the agent's state directory for
/// tools that take a path; and into each extra bundle the image named, for
/// toolchains that carry their own (Python's certifi, Node's
/// `NODE_EXTRA_CA_CERTS`). Whatever an earlier handshake installed is
/// replaced, in the store and in the bundles. An empty PEM leaves every store
/// as it is.
fn install_inspection_ca(pem: &str, extra: &[guestpb::TrustBundle]) -> anyhow::Result<()> {
    if pem.trim().is_empty() {
        return Ok(());
    }
    let mut held = installed().lock().unwrap();
    if held
        .as_ref()
        .is_some_and(|(done, bundles)| done == pem && bundles == extra)
    {
        return Ok(());
    }
    replace_in_root_store(&pem_certificates(pem)?)?;

    let dir = win::state_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("inspection-ca.pem"), pem)?;
    for bundle in extra {
        let path = win::map_path(&bundle.path)
            .map_err(|_| anyhow::anyhow!("trust bundle {:?} is not a local path", bundle.path))?;
        let existing = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound && bundle.is_created_if_missing =>
            {
                Vec::new()
            }
            Err(err) => return Err(anyhow::anyhow!("reading {path}: {err}")),
        };
        let text = crate::trust::with_ca(&existing, pem);
        if text == existing {
            continue;
        }
        // Renamed into place, so nothing reads a half-written bundle.
        let temp = format!("{path}.burrow-new");
        std::fs::write(&temp, text)?;
        std::fs::rename(&temp, &path)?;
    }
    *held = Some((pem.to_string(), extra.to_vec()));
    Ok(())
}

/// Makes `wanted` the certificates of Burrow's in the machine Root store.
///
/// What this adds is tagged with [`crate::trust::FRIENDLY_NAME`], and every
/// tagged certificate that is not wanted is deleted, so a sandbox told
/// another root stops trusting the last one. A certificate the store already
/// held is the image's and is left untagged and alone.
fn replace_in_root_store(wanted: &[Vec<u8>]) -> anyhow::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FRIENDLY_NAME_PROP_ID, CERT_STORE_ADD_NEW, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, CertAddEncodedCertificateToStore,
        CertCloseStore, CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
        CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
        CertOpenStore, CertSetCertificateContextProperty, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    const CRYPT_E_EXISTS: u32 = 0x8009_2005;
    let root = win::wide("ROOT");
    // SAFETY: `root` is NUL-terminated; the store is closed below.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            root.as_ptr().cast(),
        )
    };
    anyhow::ensure!(
        !store.is_null(),
        "opening the machine root store: {}",
        win::last_io_error()
    );
    let tag = win::wide(crate::trust::FRIENDLY_NAME);
    let result = (|| {
        // Collected first: deleting while enumerating invalidates the walk.
        let mut tagged: Vec<(Vec<u8>, *const CERT_CONTEXT)> = Vec::new();
        let mut at: *const CERT_CONTEXT = std::ptr::null();
        loop {
            // SAFETY: `at` is null or the context the last call returned,
            // which this call frees.
            at = unsafe { CertEnumCertificatesInStore(store, at) };
            if at.is_null() {
                break;
            }
            let mut name = vec![0u16; tag.len() + 1];
            let mut size = (name.len() * 2) as u32;
            // SAFETY: `name` holds `size` bytes.
            let ok = unsafe {
                CertGetCertificateContextProperty(
                    at,
                    CERT_FRIENDLY_NAME_PROP_ID,
                    name.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if ok != 0 && name[..(size as usize / 2)] == tag[..] {
                // SAFETY: a live context from the enumeration.
                let der = unsafe {
                    std::slice::from_raw_parts((*at).pbCertEncoded, (*at).cbCertEncoded as usize)
                }
                .to_vec();
                // SAFETY: as above; the duplicate outlives the walk.
                tagged.push((der, unsafe { CertDuplicateCertificateContext(at) }));
            }
        }
        let ders: Vec<&[u8]> = tagged.iter().map(|(der, _)| der.as_slice()).collect();
        let stale = crate::trust::stale(&ders, wanted);
        let mut failed = None;
        for (der, context) in &tagged {
            if stale.contains(&der.as_slice()) {
                // SAFETY: deleting frees the duplicate it is given.
                if unsafe { CertDeleteCertificateFromStore(*context) } == 0 {
                    failed.get_or_insert_with(win::last_io_error);
                }
            } else {
                // SAFETY: the duplicate taken above.
                unsafe { CertFreeCertificateContext(*context) };
            }
        }
        if let Some(err) = failed {
            anyhow::bail!("removing an earlier root from the machine root store: {err}");
        }
        for der in wanted {
            if tagged.iter().any(|(held, _)| held == der) {
                continue;
            }
            let mut added: *mut CERT_CONTEXT = std::ptr::null_mut();
            // SAFETY: `der` is the certificate's bytes, of the length passed.
            let ok = unsafe {
                CertAddEncodedCertificateToStore(
                    store,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    der.as_ptr(),
                    der.len() as u32,
                    CERT_STORE_ADD_NEW,
                    &mut added,
                )
            };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(CRYPT_E_EXISTS as i32) {
                    continue;
                }
                anyhow::bail!("adding to the machine root store: {err}");
            }
            let blob = CRYPT_INTEGER_BLOB {
                cbData: (tag.len() * 2) as u32,
                pbData: tag.as_ptr().cast_mut().cast(),
            };
            // SAFETY: `added` is the context just added; `blob` outlives the call.
            let ok = unsafe {
                CertSetCertificateContextProperty(
                    added,
                    CERT_FRIENDLY_NAME_PROP_ID,
                    0,
                    (&raw const blob).cast(),
                )
            };
            // SAFETY: returned by the add.
            unsafe { CertFreeCertificateContext(added) };
            anyhow::ensure!(
                ok != 0,
                "naming the root in the machine root store: {}",
                win::last_io_error()
            );
        }
        Ok(())
    })();
    // SAFETY: opened above.
    unsafe { CertCloseStore(store, 0) };
    result
}

/// The adapter the host's network is on, and the global IPv6 addresses it
/// holds: the first Ethernet adapter, which in a burrow VM is the one
/// virtio-net device.
fn adapter() -> anyhow::Result<(u32, Vec<std::net::Ipv6Addr>)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IF_TYPE_ETHERNET_CSMACD, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, AF_UNSPEC, SOCKADDR_IN6};
    let mut buf = vec![0u64; 2048];
    let mut size = (buf.len() * 8) as u32;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    loop {
        // SAFETY: `buf` is `size` bytes and 8-aligned.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            0 => break,
            // ERROR_BUFFER_OVERFLOW, with the size needed.
            111 => buf.resize((size as usize).div_ceil(8), 0),
            rc => anyhow::bail!(
                "GetAdaptersAddresses: {}",
                std::io::Error::from_raw_os_error(rc as i32)
            ),
        }
    }
    let mut at = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !at.is_null() {
        // SAFETY: a list the call wrote into `buf`.
        let adapter = unsafe { &*at };
        if adapter.IfType == IF_TYPE_ETHERNET_CSMACD {
            // SAFETY: the union's second form is the one Windows fills.
            let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let mut v6 = Vec::new();
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: as above.
                let address = unsafe { &*unicast };
                let sockaddr = address.Address.lpSockaddr;
                // SAFETY: the family says which sockaddr it is.
                if !sockaddr.is_null() && unsafe { (*sockaddr).sa_family } == AF_INET6 {
                    let v6addr = unsafe { &*sockaddr.cast::<SOCKADDR_IN6>() };
                    // SAFETY: the address's bytes, in either union form.
                    let ip = std::net::Ipv6Addr::from(unsafe { v6addr.sin6_addr.u.Byte });
                    // Link-local is the adapter's own and stays.
                    if ip.segments()[0] & 0xffc0 != 0xfe80 {
                        v6.push(ip);
                    }
                }
                unicast = address.Next;
            }
            return Ok((index, v6));
        }
        at = adapter.Next;
    }
    anyhow::bail!("no Ethernet adapter; is the virtio-net driver installed?")
}

/// The network last applied, so a handshake that repeats it changes nothing.
fn applied() -> &'static Mutex<Option<guestpb::NetworkConfig>> {
    static APPLIED: Mutex<Option<guestpb::NetworkConfig>> = Mutex::new(None);
    &APPLIED
}

fn apply_network(config: &guestpb::NetworkConfig) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let mut held = applied().lock().unwrap();
    if held.as_ref() == Some(config) {
        return Ok(());
    }
    let (index, v6) = adapter()?;
    for step in netcfg::steps(index, config, &v6)? {
        let output = std::process::Command::new("netsh")
            .args(&step.args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
        if step.is_required && !output.status.success() {
            anyhow::bail!(
                "netsh {} exited {}: {}",
                step.args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
    }
    tracing::debug!(ip = config.ip, index, "network applied");
    *held = Some(config.clone());
    Ok(())
}
