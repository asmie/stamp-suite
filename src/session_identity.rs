//! STAMP session identity and static reflector admission (RFC 8972 §3).

use std::{fmt, net::SocketAddr, str::FromStr};

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum SessionAdmission {
    /// Learn sessions from incoming packets (legacy interoperability mode).
    #[default]
    Permissive,
    /// Only answer explicitly provisioned session identities.
    Provisioned,
}

/// A UDP four-tuple, SSID, and optional RFC 9534 sender member identifier.
/// The reflector's member identifier is configuration, not a changing lookup
/// field: a sender can initially send zero before learning it from a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub client: SocketAddr,
    pub local: SocketAddr,
    pub ssid: u16,
    pub sender_micro_session_id: Option<u16>,
}

impl fmt::Display for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{},{}", self.ssid, self.client, self.local)?;
        if let Some(id) = self.sender_micro_session_id {
            write!(f, ",{id}")?;
        }
        Ok(())
    }
}

impl FromStr for SessionKey {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let fields: Vec<_> = spec.split(',').map(str::trim).collect();
        if !(3..=4).contains(&fields.len()) {
            return Err(
                "expected SSID,SOURCE_IP:PORT,DESTINATION_IP:PORT[,SENDER_MICRO_ID]".into(),
            );
        }
        let key = Self {
            ssid: fields[0].parse().map_err(|_| "invalid SSID")?,
            client: fields[1].parse().map_err(|_| "invalid source endpoint")?,
            local: fields[2]
                .parse()
                .map_err(|_| "invalid destination endpoint")?,
            sender_micro_session_id: fields
                .get(3)
                .map(|id| id.parse().map_err(|_| "invalid sender micro-session ID"))
                .transpose()?,
        };
        if key.client.ip().is_unspecified()
            || key.local.ip().is_unspecified()
            || key.client.port() == 0
            || key.local.port() == 0
            || key.client.is_ipv4() != key.local.is_ipv4()
        {
            return Err("session endpoints must have concrete addresses, nonzero ports, and matching address families".into());
        }
        Ok(key)
    }
}

/// Compatibility for callers of the original source-only SessionManager API.
/// Receiver backends always supply a complete SessionKey. This conversion
/// represents a base session with an unknown local endpoint, never a wildcard
/// provisioning rule.
impl From<SocketAddr> for SessionKey {
    fn from(client: SocketAddr) -> Self {
        Self {
            client,
            local: SocketAddr::new(
                if client.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            ),
            ssid: 0,
            sender_micro_session_id: None,
        }
    }
}
