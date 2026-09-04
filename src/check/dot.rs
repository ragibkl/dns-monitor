use std::{net::IpAddr, time::Instant};

use anyhow::{Context, bail};
use hickory_proto::op::{Message, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    check::{Outcome, Prober, elapsed_ms, tls_connect, truncate, with_timeout},
    config::Node,
};

const PORT: u16 = 853;

pub async fn check(prober: &Prober, node: &Node, ip: IpAddr) -> Outcome {
    let start = Instant::now();
    let result = with_timeout(prober.timeout, query(prober, node, ip)).await;
    let ms = elapsed_ms(start);

    match result {
        Ok(()) => Outcome::up("dot ok", ms),
        Err(err) => Outcome::down(truncate(&format!("dot: {err:#}")), ms),
    }
}

async fn query(prober: &Prober, node: &Node, ip: IpAddr) -> anyhow::Result<()> {
    let request = prober.query();
    let id = request.metadata.id;
    let wire = request.to_vec().context("could not encode query")?;
    let mut stream = tls_connect(prober, node, ip, PORT).await?;

    // DNS over TCP, and so over TLS, frames each message with a two-byte
    // big-endian length prefix (RFC 1035 section 4.2.2).
    let mut framed = Vec::with_capacity(2 + wire.len());
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(&wire);
    stream
        .write_all(&framed)
        .await
        .context("could not send query")?;
    stream.flush().await.context("could not flush query")?;

    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .context("could not read response length")?;

    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream
        .read_exact(&mut body)
        .await
        .context("could not read response")?;

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
