pub mod cert;
pub mod doh;
pub mod dot;

use std::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::net::{TcpStream, lookup_host};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::config::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Doh,
    Dot,
    Cert,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Doh => "doh",
            Self::Dot => "dot",
            Self::Cert => "cert",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of one check, in the shape uptime-kuma's push API takes.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub up: bool,
    pub msg: String,
    /// Latency in ms for `doh`/`dot`; days remaining for `cert`.
    pub ping: f64,
}

impl Outcome {
    pub fn up(msg: impl Into<String>, ping: f64) -> Self {
        Self {
            up: true,
            msg: msg.into(),
            ping,
        }
    }

    pub fn down(msg: impl Into<String>, ping: f64) -> Self {
        Self {
            up: false,
            msg: msg.into(),
            ping,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.up { "up" } else { "down" }
    }
}

/// Everything the three checks share for a round.
pub struct Prober {
    pub qname: Name,
    pub timeout: Duration,
    pub warn_days: i64,
    /// DoH client. Idle connections are not pooled, so every round performs a
    /// full TLS handshake and ALPN negotiation -- that is the thing being
    /// checked, and a pooled connection would silently stop exercising it.
    pub doh: reqwest::Client,
    pub tls: Arc<ClientConfig>,
}

impl Prober {
    pub fn new(qname: &str, timeout: Duration, warn_days: i64) -> anyhow::Result<Self> {
        let qname = Name::from_ascii(qname).context("invalid QNAME")?;

        let doh = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(timeout)
            .build()
            .context("could not build DoH client")?;

        // The same verifier reqwest uses, so the DoH check and the DoT and
        // certificate checks agree about what a valid chain is. Two trust
        // stores would let one monitor call a certificate good and another
        // call the same certificate bad.
        let tls = ClientConfig::builder()
            .with_platform_verifier()
            .context("could not build TLS config")?
            .with_no_client_auth();

        Ok(Self {
            qname,
            timeout,
            warn_days,
            doh,
            tls: Arc::new(tls),
        })
    }

    /// A fresh query for the configured name. The id is randomised per query,
    /// and both checks verify it on the way back, so a stale or mismatched
    /// response cannot be mistaken for a live one.
    pub fn query(&self) -> Message {
        let mut message = Message::query();
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(self.qname.clone(), RecordType::A));
        message
    }
}

/// Resolves a node's address once per round, so all three of its checks target
/// the same server and a partial round-robin cannot produce mixed results.
///
/// The trailing dot matters: a Kubernetes pod's resolv.conf carries `ndots:5`
/// and search domains, and without it the search list is tried first. The
/// Deployment also sets `ndots:1`; this is the belt to that pair of braces.
///
/// IPv4 is preferred rather than taking whichever address the resolver happened
/// to return first. These nodes are dual stack, and an arbitrary choice would
/// make the DoT and certificate checks, which connect to this address, disagree
/// with the DoH check, which resolves and falls back on its own -- showing a
/// node as half down when it is not. It also means IPv6 is not currently
/// checked; that would want its own monitors rather than a coin toss here.
pub async fn resolve(node: &Node) -> anyhow::Result<IpAddr> {
    let addrs: Vec<SocketAddr> = lookup_host(format!("{}.:0", node.host))
        .await
        .with_context(|| format!("could not resolve {}", node.host))?
        .collect();

    addrs
        .iter()
        .map(SocketAddr::ip)
        .find(IpAddr::is_ipv4)
        .or_else(|| addrs.first().map(SocketAddr::ip))
        .with_context(|| format!("no address for {}", node.host))
}

/// Elapsed time as the millisecond figure uptime-kuma graphs.
pub fn elapsed_ms(start: std::time::Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

/// Opens a verified TLS connection to one of a node's ports.
///
/// The address is the one already resolved for this round, while the name
/// offered for SNI and checked against the certificate is the node's hostname.
/// Verification is on, so a stale or expired certificate fails here rather than
/// being silently accepted.
pub async fn tls_connect(
    prober: &Prober,
    node: &Node,
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let addr = SocketAddr::new(ip, port);
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("could not connect to {addr}"))?;

    let server_name = ServerName::try_from(node.host.clone())
        .with_context(|| format!("invalid server name {}", node.host))?;

    TlsConnector::from(prober.tls.clone())
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {addr} failed"))
}

/// Bounds a check, so one unreachable node cannot hold up the round it is in.
pub async fn with_timeout<F, T>(duration: Duration, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => bail!("timed out after {duration:?}"),
    }
}

/// uptime-kuma stores a push message verbatim and shows it on one line, so keep
/// it to something that reads in the monitor list.
pub fn truncate(msg: &str) -> String {
    const MAX: usize = 110;

    let msg = msg.replace('\n', " ");
    if msg.chars().count() <= MAX {
        return msg;
    }

    msg.chars().take(MAX - 1).chain(['\u{2026}']).collect()
}
