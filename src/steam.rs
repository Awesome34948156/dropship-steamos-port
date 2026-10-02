use std::{fs, path::PathBuf, process::Command};

#[derive(Clone, Debug, Default)]
pub struct SteamInstall {
    pub root: PathBuf,
    pub proton_prefix: Option<PathBuf>,
    pub installed: bool,
    pub game_running: bool,
}

pub fn discover(app_id: u32) -> SteamInstall {
    let root = steam_roots()
        .into_iter()
        .find(|root| root.join("steamapps").is_dir());

    let Some(root) = root else {
        return SteamInstall::default();
    };

    let manifest = root.join(format!("steamapps/appmanifest_{app_id}.acf"));
    let prefix = root.join(format!("steamapps/compatdata/{app_id}/pfx"));
    SteamInstall {
        root,
        proton_prefix: prefix.is_dir().then_some(prefix),
        installed: manifest.is_file(),
        game_running: overwatch_process_running(),
    }
}

fn steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        roots.push(home.join(".local/share/Steam"));
        roots.push(home.join(".steam/steam"));
    }
    roots
}

fn overwatch_process_running() -> bool {
    let Ok(output) = Command::new("ps").args(["-eo", "args="]).output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    text.contains("overwatch.exe") || text.contains("_retail_/overwatch")
}

pub fn steam_library_hint(install: &SteamInstall) -> String {
    if install.root.as_os_str().is_empty() {
        return "Steam was not found in the current user's standard locations.".to_owned();
    }
    if !install.installed {
        return format!(
            "Steam found at {}, but this app ID is not installed.",
            install.root.display()
        );
    }
    if let Some(prefix) = &install.proton_prefix {
        return format!("Overwatch Proton prefix: {}", prefix.display());
    }
    "Overwatch is installed, but its Proton prefix has not been created yet. Launch it once from Steam.".to_owned()
}

#[allow(dead_code)]
fn _read_manifest(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path).ok()
}
