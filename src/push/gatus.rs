use std::time::Duration;

use anyhow::Context;

use crate::{
    check::{Outcome, Proto},
    config::Node,
};

/// Client for Gatus's external endpoint API.
///
/// Gatus checks most of the fleet itself, but it speaks HTTP/1.1 only -- its
/// transport sets TLSClientConfig without ForceAttemptHTTP2, which switches off
/// Go's automatic HTTP/2 -- and dnsdist 1.9+ answers DoH over HTTP/1.1 with a
/// 400. It also has no way to send a query over a DoT connection. So the two
/// checks that need a real resolution are pushed in from here.
pub struct Gatus {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl Gatus {
    pub fn new(base: &str, token: &str, timeout: Duration) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("could not build gatus client")?;

        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
        })
    }

    /// Gatus addresses an external endpoint by `<group>_<name>`, which is how
    /// it is keyed in the config rather than anything derived at runtime.
    fn key(node: &Node, proto: Proto) -> String {
        format!("{}_{}", node.short, proto)
    }

    /// Whether Gatus wants this check pushed at all.
    ///
    /// Certificates are checked by Gatus itself, with a `tls://` endpoint and a
    /// `[CERTIFICATE_EXPIRATION]` condition, so pushing them as well would give
    /// two sources for one fact. It only takes what Gatus cannot do: a query
    /// that has to actually be resolved over DoH or DoT.
    fn accepts(proto: Proto) -> bool {
        !matches!(proto, Proto::Cert)
    }

    pub async fn push(&self, node: &Node, proto: Proto, outcome: &Outcome) -> anyhow::Result<()> {
        if !Self::accepts(proto) {
            return Ok(());
        }

        let mut query: Vec<(&str, String)> =
            vec![("success", outcome.up.to_string())];

        if !outcome.up {
            query.push(("error", outcome.msg.clone()));
        }

        // Only doh and dot reach here, and for both the ping value is a latency.
        query.push(("duration", format!("{}ms", outcome.ping.round() as i64)));

        self.client
            .post(format!(
                "{}/api/v1/endpoints/{}/external",
                self.base,
                Self::key(node, proto)
            ))
            .bearer_auth(&self.token)
            .query(&query)
            .send()
            .await
            .context("push request failed")?
            .error_for_status()
            .context("push rejected")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_are_left_to_gatus_itself() {
        assert!(Gatus::accepts(Proto::Doh));
        assert!(Gatus::accepts(Proto::Dot));
        assert!(!Gatus::accepts(Proto::Cert));
    }

    #[test]
    fn key_matches_the_group_and_name_in_the_gatus_config() {
        let node = Node::new("jp-dns2", "bancuh.com");
        assert_eq!(Gatus::key(&node, Proto::Doh), "jp-dns2_doh");
        assert_eq!(Gatus::key(&node, Proto::Dot), "jp-dns2_dot");
    }
}
