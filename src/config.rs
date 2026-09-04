use std::env;

use crate::check::Proto;

/// One resolver to be checked, e.g. short `jp-dns2` in domain `bancuh.com`.
#[derive(Debug, Clone)]
pub struct Node {
    pub short: String,
    pub host: String,
}

impl Node {
    pub fn new(short: &str, domain: &str) -> Self {
        Self {
            short: short.to_string(),
            host: format!("{short}.{domain}"),
        }
    }

    /// Environment key for a push token, e.g. `TOKEN_JP_DNS2_DOH`.
    ///
    /// Tokens are read from the environment by name rather than declared as
    /// fields, so adding a node stays a config change: a new entry in `NODES`
    /// plus its three tokens in the Secret, with no code or image rebuild.
    fn token_key(&self, proto: Proto) -> String {
        let short: String = self
            .short
            .to_uppercase()
            .replace('-', "_")
            .chars()
            .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();

        format!("TOKEN_{short}_{}", proto.as_str().to_uppercase())
    }

    /// The uptime-kuma push token for one of this node's checks, if configured.
    pub fn token(&self, proto: Proto) -> Option<String> {
        let key = self.token_key(proto);
        match env::var(&key) {
            Ok(token) if !token.is_empty() => Some(token),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_short_name_in_domain() {
        let node = Node::new("jp-dns2", "bancuh.com");
        assert_eq!(node.host, "jp-dns2.bancuh.com");
    }

    #[test]
    fn token_key_uppercases_and_replaces_dashes() {
        let node = Node::new("jp-dns2", "bancuh.com");
        assert_eq!(node.token_key(Proto::Doh), "TOKEN_JP_DNS2_DOH");
        assert_eq!(node.token_key(Proto::Dot), "TOKEN_JP_DNS2_DOT");
        assert_eq!(node.token_key(Proto::Cert), "TOKEN_JP_DNS2_CERT");
    }

    #[test]
    fn token_key_drops_characters_that_cannot_appear_in_an_env_name() {
        let node = Node::new("jp.dns+2", "bancuh.com");
        assert_eq!(node.token_key(Proto::Doh), "TOKEN_JPDNS2_DOH");
    }
}
