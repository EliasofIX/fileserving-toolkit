//! fileserving-toolkit (FST) — suckless file server.

mod api;
mod auth;
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
use std::sync::Arc;
use storage::Storage;
use transfer::TransferManager;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fst", about = "fileserving-toolkit — serve files, fast and quiet")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
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
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "fst=info".into()))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.cmd.unwrap_or(Commands::Serve) {
        Commands::HashPassword { password } => {
            let h = crypto::hash_password(&password)?;
            println!("{h}");
            return Ok(());
        }
        Commands::InitKeys { username, password } => {
            let cfg = Config::load(&cli.config)?;
            cfg.ensure_dirs()?;
            let dir = crypto::keystore_dir(&cfg.server.data_dir);
            crypto::create_user_keystore(&username, &password, &dir)?;
            println!("keystore ready for {username} at {}", dir.display());
            return Ok(());
        }
        Commands::Serve => {}
    }

    let cfg = Config::load(&cli.config).map_err(|e| {
        format!(
            "failed to load {}: {e}\nCopy config.example.toml → config.toml",
            cli.config.display()
        )
    })?;

    let workers = if cfg.server.workers == 0 {
        2
    } else {
        cfg.server.workers
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    rt.block_on(serve(cfg, workers))
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
