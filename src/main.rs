mod check;
mod config;
mod health;
mod push;

use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

use anyhow::bail;
use clap::Parser;
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinSet,
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    check::{Outcome, Prober, Proto, cert, doh, dot, truncate},
    config::Node,
    health::Health,
    push::Targets,
};

/// How long a push may take. Independent of the probe timeout: this is a call
/// to an in-cluster service, not to a resolver on the internet.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// A round is late, rather than merely slow, once this many intervals pass.
const STALE_ROUNDS: u32 = 3;

/// Pause before repeating a failed check. Long enough not to land in the same
/// instant that just failed, short enough that a whole failing fleet still
/// finishes a round well inside one interval.
const CONFIRM_DELAY: Duration = Duration::from_secs(2);

#[derive(Parser, Debug)]
#[command(name = "dns-monitor")]
#[command(version)]
#[command(about)]
struct Args {
    /// Space-separated short names, e.g. "jp-dns2 jp-dns1"
    #[arg(long, env, value_name = "NODES", value_delimiter = ' ')]
    nodes: Vec<String>,

    /// Suffix appended to each short name
    #[arg(long, env, value_name = "DOMAIN", default_value = "bancuh.com")]
    domain: String,

    /// Base URL of the uptime-kuma to push results to. Unset to not push there.
    #[arg(long, env, value_name = "KUMA")]
    kuma: Option<String>,

    /// Base URL of the Gatus to push results to. Unset to not push there.
    #[arg(long, env, value_name = "GATUS")]
    gatus: Option<String>,

    /// Bearer token for the Gatus external endpoints. Required with GATUS.
    #[arg(long, env, value_name = "GATUS_TOKEN")]
    gatus_token: Option<String>,

    /// Name to resolve
    #[arg(long, env, value_name = "QNAME", default_value = "careers.opendns.com")]
    qname: String,

    /// Per-check timeout, seconds
    #[arg(long, env, value_name = "TIMEOUT", default_value = "8")]
    timeout: u64,

    /// Report a certificate down once it has fewer days than this remaining
    #[arg(long, env, value_name = "WARN_DAYS", default_value = "21")]
    warn_days: i64,

    /// Seconds between rounds of checks
    #[arg(long, env, value_name = "INTERVAL", default_value = "120")]
    interval: u64,

    /// Port for the health server
    #[arg(long, env, value_name = "HEALTH_PORT", default_value = "8080")]
    health_port: u16,
}

async fn sigint() -> std::io::Result<()> {
    signal(SignalKind::interrupt())?.recv().await;
    Ok(())
}

async fn sigterm() -> std::io::Result<()> {
    signal(SignalKind::terminate())?.recv().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let Args {
        nodes,
        domain,
        kuma,
        gatus,
        gatus_token,
        qname,
        timeout,
        warn_days,
        interval,
        health_port,
    } = Args::parse();

    if nodes.is_empty() {
        bail!("NODES is empty");
    }

    let timeout = Duration::from_secs(timeout);
    let interval = Duration::from_secs(interval);

    tracing::info!("nodes: [{}]", nodes.join(", "));
    tracing::info!("domain: {domain}");

    tracing::info!("qname: {qname}");
    tracing::info!("timeout: {timeout:?}");
    tracing::info!("warn_days: {warn_days}");
    tracing::info!("interval: {interval:?}");

    // reqwest and the raw DoT/certificate handshakes share one rustls provider.
    // Installing it up front turns a missing-provider panic deep in the first
    // round into a clear failure at startup.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let nodes: Arc<Vec<Node>> = Arc::new(
        nodes
            .iter()
            .map(|short| Node::new(short, &domain))
            .collect(),
    );
    for node in nodes.iter() {
        for proto in [Proto::Doh, Proto::Dot, Proto::Cert] {
            if node.token(proto).is_none() {
                tracing::warn!("no push token for {} {proto}", node.host);
            }
        }
    }

    let gatus = match (gatus.as_deref(), gatus_token.as_deref()) {
        (Some(base), Some(token)) => Some((base, token)),
        (Some(_), None) => bail!("GATUS is set but GATUS_TOKEN is not"),
        _ => None,
    };

    let targets = Arc::new(Targets::new(kuma.as_deref(), gatus, PUSH_TIMEOUT)?);
    if targets.is_empty() {
        bail!("no push target configured: set KUMA, GATUS, or both");
    }
    tracing::info!("pushing to: {}", targets.names().join(", "));

    let prober = Arc::new(Prober::new(&qname, timeout, warn_days)?);
    let health = Arc::new(Health::new(interval * STALE_ROUNDS));

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    tracing::info!("Starting health server on port {health_port}");
    let cloned_health = health.clone();
    let cloned_token = token.clone();
    tracker.spawn(async move {
        if let Err(err) = health::serve(health_port, cloned_health, cloned_token.clone()).await {
            tracing::error!("Health server failed: {err}");
            cloned_token.cancel();
        }
    });

    tracing::info!("Starting check loop");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // A round that overruns delays the next one rather than causing a burst
        // of catch-up rounds, which would push duplicate heartbeats.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = cloned_token.cancelled() => {
                    tracing::info!("check loop received cancel signal");
                    return;
                }
            }

            run_round(prober.clone(), targets.clone(), nodes.clone()).await;
            health.round_completed();
        }
    });

    tracker.close();

    tokio::select! {
        res = sigint() => match res {
            Ok(()) => tracing::info!("Received sigint signal"),
            Err(err) => tracing::info!("Unable to listen for sigint signal: {err}"),
        },
        res = sigterm() => match res {
            Ok(()) => tracing::info!("Received sigterm signal"),
            Err(err) => tracing::info!("Unable to listen for sigterm signal: {err}"),
        },
        _ = tracker.wait() => tracing::info!("Tasks ended prematurely"),
    }

    tracing::info!("Shutting down tasks");
    token.cancel();
    tracker.wait().await;
    tracing::info!("Shutting down tasks. DONE");

    Ok(())
}

/// Checks every node at once. The round takes as long as its slowest single
/// check, not the sum of all of them, so one unreachable region cannot delay or
/// starve the checks for the others.
async fn run_round(prober: Arc<Prober>, targets: Arc<Targets>, nodes: Arc<Vec<Node>>) {
    let started = std::time::Instant::now();

    let mut set = JoinSet::new();
    for node in nodes.iter() {
        let node = node.clone();
        let prober = prober.clone();
        let targets = targets.clone();
        set.spawn(async move { check_node(&prober, &targets, &node).await });
    }

    while let Some(joined) = set.join_next().await {
        if let Err(err) = joined {
            tracing::error!("check task panicked: {err}");
        }
    }

    tracing::info!("round finished in {:?}", started.elapsed());
}

/// Repeats a failed check once before reporting it down.
///
/// A single bad probe was enough to notify. The three alerts on 4 September
/// were each one failed check that passed again on the next round, and the
/// shell version behaved the same way. Confirming spends one extra probe on
/// the rare failing check, and a real outage still reports within the round it
/// started in rather than waiting for the next one.
///
/// Only failures are repeated. A certificate genuinely near expiry is reported
/// the first time, since asking again cannot change the answer.
async fn confirmed<F, Fut>(node: &Node, proto: Proto, run: F) -> Outcome
where
    F: Fn() -> Fut,
    Fut: Future<Output = Outcome>,
{
    let first = run().await;
    if first.up || !first.retryable {
        return first;
    }

    tracing::info!("RETRY {} {proto} after: {}", node.host, first.msg);
    tokio::time::sleep(CONFIRM_DELAY).await;
    run().await
}

/// Resolution failures take all three of a node's checks down at once, so they
/// are the loudest thing that can happen and are worth confirming too.
async fn resolve_confirmed(node: &Node) -> anyhow::Result<IpAddr> {
    match check::resolve(node).await {
        Ok(ip) => Ok(ip),
        Err(err) => {
            tracing::info!("RETRY {} resolve after: {err:#}", node.host);
            tokio::time::sleep(CONFIRM_DELAY).await;
            check::resolve(node).await
        }
    }
}

async fn check_node(prober: &Prober, targets: &Targets, node: &Node) {
    // Resolved once for the round so all three checks address the same server.
    let ip = match resolve_confirmed(node).await {
        Ok(ip) => ip,
        Err(err) => {
            // All three checks depend on the name, so all three are down. Each
            // is reported separately so its own monitor still gets a heartbeat.
            let down = |proto: Proto| Outcome::down(truncate(&format!("{proto}: {err:#}")), 0.0);
            let (doh, dot, cert) = (down(Proto::Doh), down(Proto::Dot), down(Proto::Cert));
            tokio::join!(
                report(targets, node, Proto::Doh, &doh),
                report(targets, node, Proto::Dot, &dot),
                report(targets, node, Proto::Cert, &cert),
            );
            return;
        }
    };

    let (doh, dot, cert) = tokio::join!(
        confirmed(node, Proto::Doh, || doh::check(prober, node)),
        confirmed(node, Proto::Dot, || dot::check(prober, node, ip)),
        confirmed(node, Proto::Cert, || cert::check(prober, node, ip)),
    );

    tokio::join!(
        report(targets, node, Proto::Doh, &doh),
        report(targets, node, Proto::Dot, &dot),
        report(targets, node, Proto::Cert, &cert),
    );
}

async fn report(targets: &Targets, node: &Node, proto: Proto, outcome: &Outcome) {
    // The message already names the protocol, e.g. "doh ok".
    if outcome.up {
        tracing::info!("UP {} {} ping={}", node.host, outcome.msg, outcome.ping);
    } else {
        tracing::warn!("DOWN {} {}", node.host, outcome.msg);
    }

    // A failed push is logged and left for the next round. The heartbeat window
    // on both targets is wider than one interval, so a single miss is absorbed
    // rather than being escalated into a failed run.
    targets.report(node, proto, outcome).await;
}
