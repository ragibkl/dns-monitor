use std::net::IpAddr;

use anyhow::{Context, bail};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    check::{Outcome, Prober, tls_connect, truncate, with_timeout},
    config::Node,
};

const PORT: u16 = 443;
const SECONDS_PER_DAY: i64 = 86_400;

pub async fn check(prober: &Prober, node: &Node, ip: IpAddr) -> Outcome {
    let days = match with_timeout(prober.timeout, days_remaining(prober, node, ip)).await {
        Ok(days) => days,
        Err(err) => return Outcome::down(truncate(&format!("cert: {err:#}")), 0.0),
    };

    if days < prober.warn_days {
        return Outcome::down_final(format!("cert expires in {days} days"), days as f64);
    }

    // Days remaining is pushed as the ping value so uptime-kuma graphs it. A
    // healthy fleet shows a sawtooth resetting at each renewal; a line trending
    // to zero means renewal has stopped working, visible weeks before an outage.
    Outcome::up(format!("cert ok, {days} days"), days as f64)
}

async fn days_remaining(prober: &Prober, node: &Node, ip: IpAddr) -> anyhow::Result<i64> {
    let stream = tls_connect(prober, node, ip, PORT).await?;

    let (_, connection) = stream.get_ref();
    let Some(chain) = connection.peer_certificates() else {
        bail!("server presented no certificate");
    };

    // The chain is leaf-first. Taking a later entry would track a Let's Encrypt
    // intermediate's multi-year expiry and never alert.
    let leaf = chain.first().context("server presented an empty chain")?;
    let (_, cert) = X509Certificate::from_der(leaf).context("could not parse certificate")?;

    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs() as i64;

    Ok((not_after - now) / SECONDS_PER_DAY)
}
