use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const TABLE: &str = "dropship_steamos";

/// A cgroup v2 ancestor that an nftables rule is scoped to.
///
/// `nftables(8)` documents `socket cgroupv2 level NUM`, where the level counts
/// ancestors from the cgroup root, one-based: for cgroup `a/b`, level 1 is `a`
/// and level 2 is `b`. So `level` is always the number of components in `path`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CgroupMatch {
    /// Path relative to `/sys/fs/cgroup`, with no leading slash.
    pub path: String,
    pub level: u32,
}

impl CgroupMatch {
    /// Builds a match from a `/proc/<pid>/cgroup` path such as
    /// `/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-2357570.scope`.
    pub fn from_path(path: &str) -> Result<Self> {
        let path = path.trim();
        // Zombie processes whose cgroup was already removed are reported with a
        // trailing " (deleted)" marker.
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        let path = path.trim_start_matches('/');

        let level = path.split('/').filter(|part| !part.is_empty()).count();
        let matched = Self {
            path: path.to_owned(),
            level: level as u32,
        };
        matched.validate()?;
        Ok(matched)
    }

    /// Rejects anything that could not be a plain cgroup path.
    ///
    /// This is a trust boundary, not a cosmetic check: the privileged helper
    /// runs as root and deserialises this value from JSON supplied by the
    /// unprivileged UI, then interpolates `path` into an nft script. A path that
    /// escapes its quotes would be root code execution, so the allowlist is
    /// deliberately strict.
    pub fn validate(&self) -> Result<()> {
        if self.path.is_empty() {
            bail!("cgroup path is empty");
        }
        if self.level == 0 {
            bail!("cgroup level 0 would match every process on the device");
        }

        for part in self.path.split('/') {
            if part.is_empty() {
                bail!("cgroup path contains an empty segment");
            }
            if part == "." || part == ".." {
                bail!("cgroup path contains a relative segment");
            }
        }

        // Letters, digits and the punctuation systemd uses in unit names.
        // Note that real paths may contain systemd's `\xNN` escapes; those are
        // refused rather than allowed, because a backslash is an escape
        // character inside an nft string. Refusing is the safe direction: the
        // app declines to apply and says so instead of weakening the guard.
        let allowed = self
            .path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':' | '/'));
        if !allowed {
            bail!("cgroup path contains characters that are not valid in a cgroup path");
        }

        let components = self.path.split('/').count() as u32;
        if components != self.level {
            bail!("cgroup level does not match the depth of the path");
        }
        Ok(())
    }

    /// The nftables expression that scopes a rule to this cgroup.
    pub fn nft_expr(&self) -> String {
        format!("socket cgroupv2 level {} \"{}\"", self.level, self.path)
    }
}

/// A [`CgroupMatch`] together with the identity of the cgroup object it named.
///
/// nft resolves `socket cgroupv2` when the rule is added and keeps a reference
/// to the cgroup it found, not to the path string it was given. Destroying that
/// cgroup and recreating one at the same path therefore leaves the rule
/// matching nothing, silently, while every name in sight is unchanged. That is
/// what restarting Steam does to `app-steam@autostart.service` in Desktop Mode,
/// so "are my rules still live?" cannot be answered from the path.
///
/// Measured on the Deck 2026-10-02: a rule scoped to a scratch cgroup blocked
/// traffic from that cgroup; after `rmdir` and `mkdir` at the same path (inode
/// 31366 → 31422) the identical traffic went through. Hence the inode.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScopedCgroup {
    pub cgroup: CgroupMatch,
    /// Inode of `/sys/fs/cgroup/<path>` when it was read.
    pub inode: Option<u64>,
}

impl ScopedCgroup {
    /// Reads a cgroup's current identity from the filesystem.
    pub fn of(cgroup: &CgroupMatch) -> Self {
        Self {
            cgroup: cgroup.clone(),
            inode: cgroup_inode(&cgroup.path),
        }
    }

    /// Whether rules applied against `self` still match the cgroup `live`
    /// describes. False means those rules are scoped to a cgroup object that no
    /// longer exists, so they match nothing until they are applied again.
    ///
    /// An inode that could not be read counts as a change — re-applying is
    /// harmless, matching nothing while claiming to be applied is not. Only
    /// when neither side could read one does this degrade to comparing the
    /// path, which is all that was available before.
    pub fn still_matches(&self, live: &Self) -> bool {
        self.cgroup == live.cgroup && self.inode == live.inode
    }
}

/// Inode of a cgroup directory.
///
/// A destroyed and recreated cgroup gets a fresh inode, which is the cheap
/// signal that separates "the same cgroup" from "the same path, new cgroup".
#[cfg(target_os = "linux")]
fn cgroup_inode(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/sys/fs/cgroup/{path}"))
        .ok()
        .map(|meta| meta.ino())
}

#[cfg(not(target_os = "linux"))]
fn cgroup_inode(_path: &str) -> Option<u64> {
    None
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RulePlan {
    /// Mandatory: a plan without a cgroup would block the whole device, so it
    /// cannot be represented. There is deliberately no `global()` constructor
    /// and no fallback branch anywhere in this crate.
    pub cgroup: CgroupMatch,
    pub ipv4: Vec<IpNet>,
    pub ipv6: Vec<IpNet>,
}

impl RulePlan {
    pub fn from_networks(networks: Vec<IpNet>, cgroup: CgroupMatch) -> Self {
        let (ipv4, ipv6) = networks
            .into_iter()
            .partition(|network| network.addr().is_ipv4());
        Self { cgroup, ipv4, ipv6 }
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
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
            script.push_str(&format!(
                "    {} ip daddr @blocked_ipv4 drop\n",
                self.cgroup.nft_expr()
            ));
        }
        if !self.ipv6.is_empty() {
            script.push_str(&format!(
                "    {} ip6 daddr @blocked_ipv6 drop\n",
                self.cgroup.nft_expr()
            ));
        }
        script.push_str("  }\n}\n");
        script
    }

    pub fn validate(&self) -> Result<()> {
        self.cgroup.validate()?;
        if self.is_empty() {
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
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start nft; install nftables first")?;
    child
        .stdin
        .take()
        .context("could not open nft input")?
        .write_all(plan.nft_script().as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("nft rejected the Dropship rules");
        }
        // The table was deleted above, so a failure here leaves no rules at all
        // rather than falling back to anything broader.
        bail!("nft rejected the Dropship rules: {stderr}");
    }
    Ok(())
}

/// Whether `nft list tables` output names the Dropship table.
///
/// `nft list tables` prints one `table <family> <name>` header per table, so the
/// fields are compared rather than the line searched: a rule that merely mentions
/// the name cannot be mistaken for the table itself. A trailing `{` is tolerated
/// so neither output form reads as "absent" and silently skips the removal.
fn listing_names_table(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("table")
            && fields.next() == Some("inet")
            && fields.next().map(|name| name.trim_end_matches('{')) == Some(TABLE)
    })
}

/// Whether the Dropship table exists right now.
///
/// Treats "there is nothing there" and "I could not find out" as different
/// answers. A caller surfaces a successful removal to the user as "the rules
/// are gone", so an unreadable state — not root, no nftables, no `nf_tables` in
/// the kernel — has to fail loudly rather than report a removal that never
/// happened. Only a successful listing with no matching table means absent.
///
/// Note this forks `nft`, so the watcher calls it on a heartbeat rather than on
/// every poll.
pub fn table_present() -> Result<bool> {
    let listing = Command::new("nft")
        .args(["list", "tables"])
        .output()
        .context("could not start nft; install nftables first")?;
    if !listing.status.success() {
        let stderr = String::from_utf8_lossy(&listing.stderr);
        bail!(
            "could not list nftables tables, so whether Dropship rules are installed is \
             unknown: {}",
            stderr.trim()
        );
    }
    Ok(listing_names_table(&String::from_utf8_lossy(
        &listing.stdout,
    )))
}

/// Remove the Dropship table, if it is there.
///
/// A missing table is the one case that is legitimately a success: it is
/// already disabled, and saying so costs nothing.
pub fn disable() -> Result<()> {
    if !table_present()? {
        return Ok(());
    }

    let removal = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output()
        .context("could not start nft; install nftables first")?;
    if !removal.status.success() {
        let stderr = String::from_utf8_lossy(&removal.stderr);
        bail!("nft could not remove the Dropship table: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        "user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-2357570.scope";

    fn example_cgroup() -> CgroupMatch {
        CgroupMatch::from_path(EXAMPLE).unwrap()
    }

    #[test]
    fn rule_plan_separates_address_families() {
        let plan = RulePlan::from_networks(
            vec![
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            example_cgroup(),
        );

        assert_eq!(plan.ipv4.len(), 1);
        assert_eq!(plan.ipv6.len(), 1);
        assert!(plan.nft_script().contains("ip daddr @blocked_ipv4 drop"));
        assert!(plan.nft_script().contains("ip6 daddr @blocked_ipv6 drop"));
    }

    #[test]
    fn empty_rule_plan_is_rejected() {
        assert!(
            RulePlan {
                cgroup: example_cgroup(),
                ipv4: vec![],
                ipv6: vec![]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn cgroup_level_counts_path_components() {
        assert_eq!(example_cgroup().level, 5);
        // A leading slash is not part of the level.
        assert_eq!(
            CgroupMatch::from_path("/user.slice/app.slice/app-steam-1.scope")
                .unwrap()
                .level,
            3
        );
    }

    #[test]
    fn cgroup_path_loses_its_leading_slash() {
        assert_eq!(example_cgroup().path, EXAMPLE);
    }

    #[test]
    fn deleted_suffix_is_stripped() {
        let matched = CgroupMatch::from_path(&format!("/{EXAMPLE} (deleted)")).unwrap();
        assert_eq!(matched.path, EXAMPLE);
        assert_eq!(matched.level, 5);
    }

    #[test]
    fn root_cgroup_is_rejected() {
        // Level 0 would match every process on the device.
        assert!(CgroupMatch::from_path("/").is_err());
        assert!(CgroupMatch::from_path("").is_err());
    }

    #[test]
    fn relative_segments_are_rejected() {
        assert!(CgroupMatch::from_path("/user.slice/../etc").is_err());
        assert!(CgroupMatch::from_path("/user.slice/.").is_err());
    }

    #[test]
    fn injection_attempts_are_rejected() {
        for hostile in [
            "/user.slice\" } ; drop",
            "/user.slice\"\n}",
            "/user.slice backtick`",
            "/user.slice; rm -rf /",
            "/user.slice brace{",
            "/user.slice\\x2d",
            "/user.slice space",
        ] {
            assert!(
                CgroupMatch::from_path(hostile).is_err(),
                "should have rejected {hostile:?}"
            );
        }
    }

    #[test]
    fn mismatched_level_is_rejected() {
        // A hand-crafted payload can claim any level; validation must catch it.
        assert!(
            CgroupMatch {
                path: EXAMPLE.to_owned(),
                level: 1,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn nft_script_scopes_every_rule_to_the_cgroup() {
        let plan = RulePlan::from_networks(
            vec![
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            example_cgroup(),
        );
        let script = plan.nft_script();

        let expected_v4 =
            format!("socket cgroupv2 level 5 \"{EXAMPLE}\" ip daddr @blocked_ipv4 drop");
        let expected_v6 =
            format!("socket cgroupv2 level 5 \"{EXAMPLE}\" ip6 daddr @blocked_ipv6 drop");
        assert!(script.contains(&expected_v4), "{script}");
        assert!(script.contains(&expected_v6), "{script}");

        // No rule may drop traffic without a cgroup scope. Match on the daddr
        // rules rather than the literal "drop", which also appears in the
        // table's own name.
        let rules: Vec<&str> = script
            .lines()
            .filter(|line| line.contains("daddr"))
            .collect();
        assert_eq!(rules.len(), 2, "{script}");
        for line in rules {
            assert!(line.contains("socket cgroupv2"), "unscoped rule: {line}");
            assert!(line.ends_with(" drop"), "not a drop rule: {line}");
        }
    }

    #[test]
    fn listing_finds_the_dropship_table() {
        assert!(listing_names_table(&format!("table inet {TABLE}\n")));
        assert!(listing_names_table(&format!(
            "table ip nat\ntable inet {TABLE}\n"
        )));
        // `nft list table` prints a brace; stay tolerant of either form so a
        // formatting change cannot be read as "absent" and skip the removal.
        assert!(listing_names_table(&format!("table inet {TABLE} {{\n")));
    }

    #[test]
    fn listing_ignores_anything_that_is_not_the_dropship_table() {
        assert!(!listing_names_table(""));
        assert!(!listing_names_table("table inet dropship_spike\n"));
        // Right name, wrong family.
        assert!(!listing_names_table(&format!("table ip {TABLE}\n")));
        // A rule mentioning the name is not a table header.
        assert!(!listing_names_table(&format!(
            "\t\tip daddr @{TABLE} drop\n"
        )));
        // A table whose name merely starts with ours.
        assert!(!listing_names_table(&format!("table inet {TABLE}_old\n")));
    }

    #[test]
    fn a_recreated_cgroup_is_not_the_same_scope() {
        // The measured failure: identical path, new cgroup object. Every path
        // comparison says "unchanged", which is why this went unnoticed.
        let before = ScopedCgroup {
            cgroup: example_cgroup(),
            inode: Some(31_366),
        };
        let after = ScopedCgroup {
            cgroup: example_cgroup(),
            inode: Some(31_422),
        };

        assert_eq!(before.cgroup.path, after.cgroup.path);
        assert!(!before.still_matches(&after));
    }

    #[test]
    fn the_same_cgroup_object_still_matches() {
        let cgroup = example_cgroup();
        let applied = ScopedCgroup {
            cgroup: cgroup.clone(),
            inode: Some(7),
        };
        assert!(applied.still_matches(&ScopedCgroup {
            cgroup,
            inode: Some(7)
        }));
    }

    #[test]
    fn a_different_cgroup_never_matches() {
        let applied = ScopedCgroup {
            cgroup: example_cgroup(),
            inode: Some(7),
        };
        let live = ScopedCgroup {
            cgroup: CgroupMatch::from_path("/user.slice/app.slice/app-steam-1.scope").unwrap(),
            inode: Some(7),
        };
        assert!(!applied.still_matches(&live));
    }

    #[test]
    fn an_unreadable_inode_is_treated_as_a_change() {
        // Prompting is recoverable; reporting rules as applied while unable to
        // confirm which cgroup they are bound to is not.
        let cgroup = example_cgroup();
        let applied = ScopedCgroup {
            cgroup: cgroup.clone(),
            inode: Some(7),
        };
        assert!(!applied.still_matches(&ScopedCgroup {
            cgroup,
            inode: None
        }));
    }

    #[test]
    fn without_any_inode_this_degrades_to_the_path() {
        // Non-Linux, or a filesystem that will not say: same path still counts
        // as the same scope, which is all the old check could do.
        let cgroup = example_cgroup();
        let applied = ScopedCgroup {
            cgroup: cgroup.clone(),
            inode: None,
        };
        assert!(applied.still_matches(&ScopedCgroup {
            cgroup,
            inode: None
        }));
    }
}
