//! fileserving-toolkit (FST) — suckless file server.

mod api;
mod audio_meta;
mod auth;
mod cli;
mod config;
mod crypto;
mod media;
mod storage;
mod transfer;

use api::AppState;
use auth::AuthState;
use clap::{Parser, Subcommand};
use config::Config;
use media::Media;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use storage::Storage;
use transfer::TransferManager;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fst", about = "fileserving-toolkit — serve files, fast and quiet")]
struct Cli {
    /// Server config (serve / init-keys only)
    #[arg(short, long, default_value = "config.toml", global = true)]
    config: PathBuf,

    /// Remote server URL (or FST_URL)
    #[arg(long, global = true, env = "FST_URL")]
    url: Option<String>,

    /// Remote username (or FST_USER)
    #[arg(long, global = true, env = "FST_USER")]
    user: Option<String>,

    /// Remote password (or FST_PASSWORD)
    #[arg(long, global = true, env = "FST_PASSWORD")]
    password: Option<String>,

    /// Path to credentials.toml (default: ~/.config/fst/credentials.toml)
    #[arg(long, global = true)]
    credentials: Option<PathBuf>,

    /// Machine-readable JSON output for remote commands
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Hash a password for config.toml (Argon2id)
    HashPassword { password: String },
    /// Create / rotate a user's ML-KEM keystore (encryption mode)
    InitKeys {
        username: String,
        password: String,
    },
    /// Run the server (default)
    Serve,

    // —— remote client (agent / human) ——
    /// Log in and cache a session
    Login,
    /// Log out and clear the cached session
    Logout,
    /// Show current remote identity
    Whoami,
    /// List a directory (empty path = roots)
    Ls {
        #[arg(default_value = "")]
        path: String,
    },
    /// Create a directory
    Mkdir { path: String },
    /// Delete a file or directory
    Rm { path: String },
    /// Rename / move within the same space (shared↔shared or ~user↔~user)
    Mv { from: String, to: String },
    /// Upload a local file (resumable)
    Put { local: PathBuf, remote: String },
    /// Download a remote file
    Get {
        remote: String,
        local: Option<PathBuf>,
    },
    /// Write a remote file to stdout
    Cat { remote: String },
}

fn remote_opts(cli: &Cli) -> cli::RemoteOpts {
    cli::RemoteOpts {
        url: cli.url.clone(),
        user: cli.user.clone(),
        password: cli.password.clone(),
        credentials: cli.credentials.clone(),
        json: cli.json,
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "fst=info".into()))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run(cli: Cli) -> Result<(), u8> {
    match cli.cmd.clone().unwrap_or(Commands::Serve) {
        Commands::HashPassword { password } => {
            let h = crypto::hash_password(&password).map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })?;
            println!("{h}");
            Ok(())
        }
        Commands::InitKeys { username, password } => {
            let cfg = Config::load(&cli.config).map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })?;
            cfg.ensure_dirs().map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })?;
            let dir = crypto::keystore_dir(&cfg.server.data_dir);
            crypto::create_user_keystore(&username, &password, &dir).map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })?;
            println!("keystore ready for {username} at {}", dir.display());
            Ok(())
        }
        Commands::Serve => {
            let cfg = Config::load(&cli.config).map_err(|e| {
                eprintln!(
                    "failed to load {}: {e}\nCopy config.example.toml → config.toml",
                    cli.config.display()
                );
                1u8
            })?;
            let workers = if cfg.server.workers == 0 {
                2
            } else {
                cfg.server.workers
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .build()
                .map_err(|e| {
                    eprintln!("error: {e}");
                    1u8
                })?;
            rt.block_on(serve(cfg, workers)).map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })
        }
        cmd => {
            let opts = remote_opts(&cli);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    eprintln!("error: {e}");
                    1u8
                })?;
            let result = rt.block_on(async {
                match cmd {
                    Commands::Login => cli::cmd_login(&opts).await,
                    Commands::Logout => cli::cmd_logout(&opts).await,
                    Commands::Whoami => cli::cmd_whoami(&opts).await,
                    Commands::Ls { path } => {
                        let p = if path.is_empty() { None } else { Some(path) };
                        cli::cmd_ls(&opts, p).await
                    }
                    Commands::Mkdir { path } => cli::cmd_mkdir(&opts, path).await,
                    Commands::Rm { path } => cli::cmd_rm(&opts, path).await,
                    Commands::Mv { from, to } => cli::cmd_mv(&opts, from, to).await,
                    Commands::Put { local, remote } => cli::cmd_put(&opts, local, remote).await,
                    Commands::Get { remote, local } => cli::cmd_get(&opts, remote, local).await,
                    Commands::Cat { remote } => cli::cmd_cat(&opts, remote).await,
                    _ => unreachable!(),
                }
            });
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    eprintln!("error: {e}");
                    Err(cli::exit_code(&e) as u8)
                }
            }
        }
    }
}

async fn serve(
    cfg: Config,
    workers: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    cfg.ensure_dirs()?;

    if cfg.encryption.enabled {
        for u in &cfg.auth.users {
            if u.password_hash.is_empty() {
                tracing::warn!(
                    "user '{}' has empty password_hash — login will fail until you set one",
                    u.username
                );
            }
        }
    }

    let storage = Arc::new(Storage::new(&cfg));
    let auth = Arc::new(AuthState::new(&cfg));

    if cfg.encryption.enabled {
        match std::env::var("FST_SHARED_PASSWORD") {
            Ok(pw) if !pw.is_empty() => {
                let ks = auth.keystore_path().clone();
                let ek = ks.join("shared.ek");
                if !ek.exists() {
                    crypto::create_user_keystore("shared", &pw, &ks)?;
                    tracing::info!("created shared keystore");
                }
                match crypto::unlock_user_secrets("shared", &pw, &ks) {
                    Ok(secrets) => {
                        auth.set_shared_secrets(secrets);
                        tracing::info!("shared keystore unlocked");
                    }
                    Err(e) => tracing::error!("failed to unlock shared keystore: {e}"),
                }
            }
            _ => {
                tracing::warn!(
                    "encryption on but FST_SHARED_PASSWORD unset — shared/ uploads will fail to seal/open"
                );
            }
        }
    }

    let transfers = Arc::new(TransferManager::new(&cfg, storage.clone()));
    let media = Arc::new(Media::new(&cfg.media).await);

    let state = AppState {
        cfg: Arc::new(cfg.clone()),
        auth: auth.clone(),
        storage,
        transfers: transfers.clone(),
        media,
    };

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            auth.purge_expired();
            transfers.gc();
        }
    });

    let app = api::router(state);
    let addr: SocketAddr = cfg
        .server
        .bind
        .parse()
        .map_err(|e| format!("bad bind address: {e}"))?;

    tracing::info!(
        "FST listening on http://{addr}  encryption={}  workers={workers}",
        cfg.encryption.enabled
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
