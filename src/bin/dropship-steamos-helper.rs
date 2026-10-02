use std::io::Read;

use anyhow::{Context, Result, bail};
use dropship_steamos::firewall;

fn main() -> Result<()> {
    let action = std::env::args()
        .nth(1)
        .context("usage: dropship-steamos-helper <apply|disable>")?;
    match action.as_str() {
        "apply" => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let plan: firewall::RulePlan =
                serde_json::from_str(&input).context("invalid firewall plan")?;
            firewall::apply(&plan)
        }
        "disable" => firewall::disable(),
        _ => bail!("usage: dropship-steamos-helper <apply|disable>"),
    }
}
