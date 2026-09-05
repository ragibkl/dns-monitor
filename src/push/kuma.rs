use std::time::Duration;

use anyhow::Context;

use crate::{
    check::{Outcome, Proto},
    config::Node,
};

/// Client for uptime-kuma's push API.
pub struct Kuma {
    base: String,
    client: reqwest::Client,
}

impl Kuma {
    pub fn new(base: &str, timeout: Duration) -> anyhow::Result<Self> {
        // Unlike the probe clients, this one pools connections. A cold
        // connection to the in-cluster service was the most common failure of
        // the CronJob this replaces: a push would stall on the 10s timeout,
        // fail the run, and cause the whole suite to be repeated.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("could not build uptime-kuma client")?;

        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub async fn push(&self, node: &Node, proto: Proto, outcome: &Outcome) -> anyhow::Result<()> {
        let Some(token) = node.token(proto) else {
            tracing::warn!("no push token for {} {proto}, skipping push", node.host);
            return Ok(());
        };

        self.client
            .get(format!("{}/api/push/{token}", self.base))
            .query(&[
                ("status", outcome.status().to_string()),
                ("msg", outcome.msg.clone()),
                ("ping", outcome.ping.to_string()),
            ])
            .send()
            .await
            .context("push request failed")?
            .error_for_status()
            .context("push rejected")?;

        Ok(())
    }
}
