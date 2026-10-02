use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const TABLE: &str = "dropship_steamos";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RulePlan {
    pub ipv4: Vec<IpNet>,
    pub ipv6: Vec<IpNet>,
}

impl RulePlan {
    pub fn from_networks(networks: Vec<IpNet>) -> Self {
        let (ipv4, ipv6) = networks
            .into_iter()
            .partition(|network| network.addr().is_ipv4());
        Self { ipv4, ipv6 }
    }

    pub fn nft_script(&self) -> String {
        let mut script = format!("table inet {TABLE} {{\n");
        if !self.ipv4.is_empty() {
            script.push_str("  set blocked_ipv4 { type ipv4_addr; flags interval; elements = { ");
            script.push_str(
                &self
                    .ipv4
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            script.push_str(" } }\n");
        }
        if !self.ipv6.is_empty() {
            script.push_str("  set blocked_ipv6 { type ipv6_addr; flags interval; elements = { ");
            script.push_str(
                &self
                    .ipv6
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            script.push_str(" } }\n");
        }
        script
            .push_str("  chain output { type filter hook output priority filter; policy accept;\n");
        if !self.ipv4.is_empty() {
            script.push_str("    ip daddr @blocked_ipv4 drop\n");
        }
        if !self.ipv6.is_empty() {
            script.push_str("    ip6 daddr @blocked_ipv6 drop\n");
        }
        script.push_str("  }\n}\n");
        script
    }

    pub fn validate(&self) -> Result<()> {
        if self.ipv4.is_empty() && self.ipv6.is_empty() {
            bail!("refusing to install an empty firewall plan; use disable instead");
        }
        Ok(())
    }
}

pub fn apply(plan: &RulePlan) -> Result<()> {
    plan.validate()?;
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .status();
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("could not start nft; install nftables first")?;
    child
        .stdin
        .take()
        .context("could not open nft input")?
        .write_all(plan.nft_script().as_bytes())?;
    if !child.wait()?.success() {
        bail!("nft rejected the Dropship rules");
    }
    Ok(())
}

pub fn disable() -> Result<()> {
    let exists = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .status()
        .context("could not start nft; install nftables first")?
        .success();
    if !exists {
        return Ok(());
    }

    let status = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .status()
        .context("could not start nft; install nftables first")?;
    if !status.success() {
        bail!("Dropship table did not exist or nft could not remove it");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_plan_separates_address_families() {
        let plan = RulePlan::from_networks(vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);

        assert_eq!(plan.ipv4.len(), 1);
        assert_eq!(plan.ipv6.len(), 1);
        assert!(plan.nft_script().contains("ip daddr @blocked_ipv4 drop"));
        assert!(plan.nft_script().contains("ip6 daddr @blocked_ipv6 drop"));
    }

    #[test]
    fn empty_rule_plan_is_rejected() {
        assert!(
            RulePlan {
                ipv4: vec![],
                ipv6: vec![]
            }
            .validate()
            .is_err()
        );
    }
}
