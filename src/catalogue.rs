use std::{collections::BTreeSet, time::Duration};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const CATALOGUE_URL: &str = "https://stowmyy.github.io/dropship/ips.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Catalogue {
    /// Upstream announcements. Carried by the catalogue but not shown yet.
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
    /// The upstream comma-separated CIDR list, kept for diagnostics.
    pub block: String,
    /// `block`, parsed and validated once by [`parse`].
    ///
    /// Skipped on the wire: it is derived from `block`, and parsing it here is
    /// what keeps the per-frame selection path free of CIDR parsing.
    #[serde(skip)]
    pub ranges: Vec<IpNet>,
}

/// How long to wait for the catalogue.
///
/// Bounded on purpose: without this a stalled connection pins the fetching
/// thread and its channel forever, and the window sits on "Refreshing the
/// server catalogue…" with no way out but a restart.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub fn fetch() -> Result<Catalogue> {
    let response = reqwest::blocking::Client::builder()
        .user_agent("dropship-steamos/0.1")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()?
        .get(CATALOGUE_URL)
        .send()
        .context("could not download the server catalogue")?
        .error_for_status()
        .context("server catalogue request was rejected")?;

    let body = response
        .bytes()
        .context("could not read the server catalogue")?;
    parse(&body)
}

/// Parses and validates catalogue bytes, without touching the network.
///
/// Split out from [`fetch`] so the schema and hostile-input tests need no HTTP,
/// the same way `service_config::parse` is.
pub fn parse(bytes: &[u8]) -> Result<Catalogue> {
    let mut catalogue: Catalogue =
        serde_json::from_slice(bytes).context("server catalogue was not valid JSON")?;
    validate(&mut catalogue)?;
    Ok(catalogue)
}

/// Every selected network, both families, deduplicated.
///
/// The ranges were parsed and validated by [`parse`], so this cannot fail: a
/// malformed catalogue never reaches it.
pub fn selected_networks(catalogue: &Catalogue, selected: &BTreeSet<String>) -> Vec<IpNet> {
    let mut networks = BTreeSet::new();
    for server in catalogue
        .servers
        .overwatch
        .iter()
        .filter(|server| selected.contains(&server.token))
    {
        networks.extend(server.ranges.iter().copied());
    }
    networks.into_iter().collect()
}

fn validate(catalogue: &mut Catalogue) -> Result<()> {
    let mut tokens = BTreeSet::new();
    for server in &mut catalogue.servers.overwatch {
        if server.token.is_empty() || !tokens.insert(server.token.clone()) {
            bail!("server catalogue has a missing or duplicate token");
        }
        if server.block.trim().is_empty() {
            bail!("{} does not have block ranges", server.token);
        }
        // Parse every entry now, not when it is selected: a broken catalogue
        // must fail the fetch, where the GUI keeps the last good one, rather
        // than make the blocking contract silently unbuildable later.
        server.ranges = server
            .block
            .split(',')
            .map(|network| {
                network.trim().parse::<IpNet>().with_context(|| {
                    format!("{} contains invalid network {network:?}", server.token)
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(block: &str) -> Vec<u8> {
        format!(
            r#"{{"servers":{{"overwatch":[{{"title":"Test","token":"tst","block":"{block}"}}]}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_valid_catalogue_prepares_the_ranges() {
        let catalogue = parse(&json("192.0.2.0/24, 2001:db8::/32")).unwrap();
        let server = &catalogue.servers.overwatch[0];
        assert_eq!(server.ranges.len(), 2);
        assert!(server.ranges.contains(&"192.0.2.0/24".parse().unwrap()));
    }

    #[test]
    fn an_invalid_cidr_is_refused_at_parse_time() {
        // The old code only failed when the server was selected, and the GUI
        // then swallowed that error while reporting the catalogue as current.
        assert!(parse(&json("192.0.2.0/24, not-an-address")).is_err());
    }

    #[test]
    fn an_empty_block_is_refused() {
        assert!(parse(&json("  ")).is_err());
    }

    #[test]
    fn a_duplicate_token_is_refused() {
        let bytes = br#"{"servers":{"overwatch":[
            {"title":"A","token":"dup","block":"192.0.2.0/24"},
            {"title":"B","token":"dup","block":"198.51.100.0/24"}
        ]}}"#;
        assert!(parse(bytes).is_err());
    }

    #[test]
    fn upstream_fields_we_do_not_use_are_ignored() {
        // `bit` and `ping` were removed from the struct; an upstream catalogue
        // that still carries them must keep parsing.
        let bytes = br#"{"notices":[{"title":"n","date":"d","paragraph":"p"}],
            "servers":{"overwatch":[
                {"title":"A","token":"tst","block":"192.0.2.0/24","bit":1,"ping":"x"}
            ]}}"#;
        let catalogue = parse(bytes).unwrap();
        assert_eq!(catalogue.notices.len(), 1);
        assert_eq!(catalogue.servers.overwatch[0].ranges.len(), 1);
    }

    #[test]
    fn selected_networks_merges_and_deduplicates() {
        let bytes = br#"{"servers":{"overwatch":[
            {"title":"A","token":"a","block":"192.0.2.0/24, 2001:db8::/32"},
            {"title":"B","token":"b","block":"192.0.2.0/24"},
            {"title":"C","token":"c","block":"198.51.100.0/24"}
        ]}}"#;
        let catalogue = parse(bytes).unwrap();
        let selected = BTreeSet::from(["a".to_owned(), "b".to_owned()]);
        let networks = selected_networks(&catalogue, &selected);
        assert_eq!(networks.len(), 2);
        assert!(networks.contains(&"192.0.2.0/24".parse().unwrap()));
        assert!(networks.contains(&"2001:db8::/32".parse().unwrap()));
    }

    #[test]
    fn an_empty_selection_selects_nothing() {
        let catalogue = parse(&json("192.0.2.0/24")).unwrap();
        assert!(selected_networks(&catalogue, &BTreeSet::new()).is_empty());
    }
}
