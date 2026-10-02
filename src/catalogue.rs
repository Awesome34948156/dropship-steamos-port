use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const CATALOGUE_URL: &str = "https://stowmyy.github.io/dropship/ips.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Catalogue {
    #[serde(default)]
    pub notices: Vec<Notice>,
    pub servers: Servers,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Servers {
    #[serde(default)]
    pub overwatch: Vec<Server>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Notice {
    pub title: String,
    pub date: String,
    pub paragraph: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Server {
    pub title: String,
    pub token: String,
    pub block: String,
    pub bit: u8,
    pub ping: String,
}

pub fn fetch() -> Result<Catalogue> {
    let response = reqwest::blocking::Client::builder()
        .user_agent("dropship-steamos/0.1")
        .build()?
        .get(CATALOGUE_URL)
        .send()
        .context("could not download the server catalogue")?
        .error_for_status()
        .context("server catalogue request was rejected")?;

    let catalogue = response
        .json::<Catalogue>()
        .context("server catalogue was not valid JSON")?;
    validate(&catalogue)?;
    Ok(catalogue)
}

pub fn selected_networks(catalogue: &Catalogue, selected: &BTreeSet<String>) -> Result<Vec<IpNet>> {
    let mut networks = BTreeSet::new();
    for server in catalogue
        .servers
        .overwatch
        .iter()
        .filter(|server| selected.contains(&server.token))
    {
        for network in server.block.split(',') {
            networks.insert(network.trim().parse::<IpNet>().with_context(|| {
                format!("{} contains invalid network {network:?}", server.token)
            })?);
        }
    }
    Ok(networks.into_iter().collect())
}

fn validate(catalogue: &Catalogue) -> Result<()> {
    let mut tokens = BTreeSet::new();
    for server in &catalogue.servers.overwatch {
        if server.token.is_empty() || !tokens.insert(&server.token) {
            bail!("server catalogue has a missing or duplicate token");
        }
        if server.bit >= 64 {
            bail!("{} uses an unsupported selection bit", server.token);
        }
        if server.block.trim().is_empty() {
            bail!("{} does not have block ranges", server.token);
        }
    }
    Ok(())
}
