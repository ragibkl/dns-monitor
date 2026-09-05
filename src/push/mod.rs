mod gatus;
mod kuma;

use std::time::Duration;

use crate::{
    check::{Outcome, Proto},
    config::Node,
};

pub use self::{gatus::Gatus, kuma::Kuma};

/// Where results are reported. Both targets can be configured at once, which is
/// what makes a migration between them observable: each keeps a full history,
/// so they can be compared before either is switched off.
#[derive(Default)]
pub struct Targets {
    kuma: Option<Kuma>,
    gatus: Option<Gatus>,
}

impl Targets {
    pub fn new(
        kuma: Option<&str>,
        gatus: Option<(&str, &str)>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            kuma: kuma.map(|base| Kuma::new(base, timeout)).transpose()?,
            gatus: gatus
                .map(|(base, token)| Gatus::new(base, token, timeout))
                .transpose()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.kuma.is_none() && self.gatus.is_none()
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.kuma.is_some() {
            names.push("uptime-kuma");
        }
        if self.gatus.is_some() {
            names.push("gatus");
        }
        names
    }

    /// Reports one outcome to every configured target.
    ///
    /// Targets are pushed concurrently and failures are independent: one
    /// unreachable status page must not stop the other from being told, which
    /// matters most during a migration when one of the two is the one being
    /// trusted.
    pub async fn report(&self, node: &Node, proto: Proto, outcome: &Outcome) {
        let kuma = async {
            if let Some(kuma) = &self.kuma
                && let Err(err) = kuma.push(node, proto, outcome).await
            {
                tracing::warn!("uptime-kuma push failed for {} {proto}: {err:#}", node.host);
            }
        };

        let gatus = async {
            if let Some(gatus) = &self.gatus
                && let Err(err) = gatus.push(node, proto, outcome).await
            {
                tracing::warn!("gatus push failed for {} {proto}: {err:#}", node.host);
            }
        };

        tokio::join!(kuma, gatus);
    }
}
