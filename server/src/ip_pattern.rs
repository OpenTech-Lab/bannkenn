use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpPattern {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpPattern {
    fn parse(value: &str) -> Option<Self> {
        let (ip_text, prefix_text) = match value.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (value, None),
        };

        match ip_text.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                let prefix = match prefix_text {
                    Some(prefix) => prefix.parse::<u8>().ok()?,
                    None => 32,
                };
                if prefix > 32 {
                    return None;
                }
                Some(Self::V4 {
                    network: mask_v4(u32::from(ip), prefix),
                    prefix,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = match prefix_text {
                    Some(prefix) => prefix.parse::<u8>().ok()?,
                    None => 128,
                };
                if prefix > 128 {
                    return None;
                }
                Some(Self::V6 {
                    network: mask_v6(u128::from(ip), prefix),
                    prefix,
                })
            }
        }
    }

    fn render(self) -> String {
        match self {
            Self::V4 { network, prefix } => {
                let ip = Ipv4Addr::from(network);
                if prefix == 32 {
                    ip.to_string()
                } else {
                    format!("{}/{}", ip, prefix)
                }
            }
            Self::V6 { network, prefix } => {
                let ip = Ipv6Addr::from(network);
                if prefix == 128 {
                    ip.to_string()
                } else {
                    format!("{}/{}", ip, prefix)
                }
            }
        }
    }

    fn covers(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::V4 { network, prefix },
                Self::V4 {
                    network: other_network,
                    prefix: other_prefix,
                },
            ) => prefix <= other_prefix && mask_v4(other_network, prefix) == network,
            (
                Self::V6 { network, prefix },
                Self::V6 {
                    network: other_network,
                    prefix: other_prefix,
                },
            ) => prefix <= other_prefix && mask_v6(other_network, prefix) == network,
            _ => false,
        }
    }
}

fn mask_v4(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix == 32 {
        value
    } else {
        value & (!0u32 << (32 - prefix))
    }
}

fn mask_v6(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix == 128 {
        value
    } else {
        value & (!0u128 << (128 - prefix))
    }
}

pub fn canonicalize_ip_pattern(value: &str) -> Option<String> {
    IpPattern::parse(value).map(IpPattern::render)
}

pub fn pattern_covers_pattern(pattern: &str, target: &str) -> bool {
    match (IpPattern::parse(pattern), IpPattern::parse(target)) {
        (Some(pattern), Some(target)) => pattern.covers(target),
        _ => false,
    }
}
