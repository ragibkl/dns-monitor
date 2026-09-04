use std::time::Instant;

use anyhow::{Context, bail};
use hickory_proto::op::{Message, ResponseCode};
use reqwest::{
    Version,
    header::{ACCEPT, CONTENT_TYPE},
};

use crate::{
    check::{Outcome, Prober, elapsed_ms, truncate},
    config::Node,
};

const DNS_MESSAGE: &str = "application/dns-message";

pub async fn check(prober: &Prober, node: &Node) -> Outcome {
    let start = Instant::now();
    let result = query(prober, node).await;
    let ms = elapsed_ms(start);

    match result {
        Ok(()) => Outcome::up("doh ok", ms),
        Err(err) => Outcome::down(truncate(&format!("doh: {err:#}")), ms),
    }
}

async fn query(prober: &Prober, node: &Node) -> anyhow::Result<()> {
    let request = prober.query();
    let id = request.metadata.id;
    let wire = request.to_vec().context("could not encode query")?;

    let response = prober
        .doh
        .post(format!("https://{}/dns-query", node.host))
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .body(wire)
        .send()
        .await
        .context("request failed")?;

    // dnsdist 1.9+ enforces RFC 8484 section 5.2 and rejects DoH over HTTP/1.1
    // with a 400, so in practice a 2xx already implies h2. Assert it anyway:
    // that assertion is the reason this check exists rather than an uptime-kuma
    // HTTP(s) monitor, and a 2xx alone would not catch a downgrade.
    let version = response.version();
    if version != Version::HTTP_2 {
        bail!("did not negotiate HTTP/2 (got {version:?})");
    }

    let status = response.status();
    if !status.is_success() {
        bail!("HTTP {status}");
    }

    let body = response.bytes().await.context("could not read response")?;
    let message = Message::from_vec(&body).context("could not parse response")?;

    if message.metadata.id != id {
        bail!("response id {} does not match query {id}", message.metadata.id);
    }

    let rcode = message.metadata.response_code;
    if rcode != ResponseCode::NoError {
        bail!("status: {rcode}");
    }

    Ok(())
}
