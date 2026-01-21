mod config;
mod keepass_store;
mod truenas;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use keepass_store::{ensure_non_empty, require_entry, required_field};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "naslock",
    version,
    about = "Unlock TrueNAS datasets using KeePass"
)]
struct Cli {
    #[arg(short, long, env = "NASLOCK_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Unlock { volume: String },
}

enum StoredAuth {
    Basic {
        username: Zeroizing<String>,
        password: Zeroizing<String>,
    },
    ApiKey {
        key: Zeroizing<String>,
    },
}

impl StoredAuth {
    fn as_auth(&self) -> truenas::Auth<'_> {
        match self {
            StoredAuth::Basic { username, password } => truenas::Auth::Basic {
                username: username.as_str(),
                password: password.as_str(),
            },
            StoredAuth::ApiKey { key } => truenas::Auth::ApiKey { key: key.as_str() },
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config)?;
    let cfg = config::Config::load(&config_path)?;

    match cli.command {
        Command::Unlock { volume } => unlock_volume(&cfg, &volume),
    }
}

fn resolve_config_path(cli_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = cli_path {
        return Ok(config::expand_path(&path, None));
    }
    config::default_config_path()
}

fn unlock_volume(cfg: &config::Config, volume_name: &str) -> Result<()> {
    let volume = cfg
        .volume
        .get(volume_name)
        .with_context(|| format!("unknown volume '{}'", volume_name))?;
    let nas = cfg
        .nas
        .get(&volume.nas)
        .with_context(|| format!("unknown NAS '{}'", volume.nas))?;

    let master_password = Zeroizing::new(rpassword::prompt_password("KeePass password: ")?);

    let store = keepass_store::KeePassStore::open(
        &cfg.keepass.path,
        cfg.keepass.key_file.as_deref(),
        master_password.as_str(),
    )?;

    let auth_entry = require_entry(&store, &nas.auth_entry)?;
    let unlock_entry = require_entry(&store, &volume.unlock_entry)?;

    let stored_auth = match nas.auth_method {
        config::AuthMethod::Basic => {
            let username = required_field(auth_entry, &nas.username_field, &nas.auth_entry)?;
            let password = required_field(auth_entry, &nas.password_field, &nas.auth_entry)?;
            ensure_non_empty(username.as_str(), "NAS username")?;
            ensure_non_empty(password.as_str(), "NAS password")?;
            StoredAuth::Basic { username, password }
        }
        config::AuthMethod::ApiKey => {
            let key = required_field(auth_entry, &nas.password_field, &nas.auth_entry)?;
            ensure_non_empty(key.as_str(), "API key")?;
            StoredAuth::ApiKey { key }
        }
    };

    let unlock_secret_value =
        required_field(unlock_entry, &volume.unlock_field, &volume.unlock_entry)?;
    ensure_non_empty(unlock_secret_value.as_str(), "unlock secret")?;

    let unlock_secret = match volume.unlock_mode {
        config::UnlockMode::Passphrase => {
            truenas::UnlockSecret::Passphrase(unlock_secret_value.as_str())
        }
        config::UnlockMode::Key => truenas::UnlockSecret::Key(unlock_secret_value.as_str()),
    };

    let client = truenas::build_client(nas.skip_tls_verify)?;
    let base_url = truenas::parse_base_url(&nas.host)?;

    let options = truenas::UnlockOptions {
        recursive: volume.recursive,
        force: volume.force,
        toggle_attachments: volume.toggle_attachments,
    };

    let result = truenas::unlock_dataset(
        &client,
        &base_url,
        stored_auth.as_auth(),
        &volume.dataset,
        unlock_secret,
        options,
    )?;

    if !result.failed.is_empty() {
        for (name, reason) in &result.failed {
            eprintln!("failed to unlock {}: {}", name, reason);
        }
        bail!("unlock failed");
    }

    if let Some(job_id) = result.job_id {
        let job = truenas::wait_for_job(&client, &base_url, stored_auth.as_auth(), job_id)?;
        println!("unlock complete (job id: {})", job.id);
        return Ok(());
    }

    if !result.unlocked.is_empty() {
        println!("unlocked datasets: {}", result.unlocked.join(", "));
        return Ok(());
    }

    if let Some(message) = result.message {
        println!("{}", message);
        return Ok(());
    }

    println!("unlock request accepted");
    Ok(())
}
