use std::net::SocketAddr;
use std::path::Path;

use dcl_facilitator::api;
use dcl_facilitator::chain::{BaseRpc, Relayer};
use dcl_facilitator::config::Config;
use dcl_facilitator::store::Store;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    let rpc = match cfg.base_rpc_url.as_deref() {
        Some(url) => Some(BaseRpc::connect(url).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to build the Base RPC client",
            )
        })?),
        None => None,
    };
    let store = match cfg.database_path.as_deref() {
        Some(path) => Some(Store::open(path).await?),
        None => None,
    };
    let relayer = match cfg.settler_key_file.as_deref() {
        Some(path) => Some(Relayer::from_file(Path::new(path)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "invalid settler key file")
        })?),
        None => None,
    };
    if cfg.settler_key_file.is_some() && cfg.oracle_address.is_none() {
        tracing::warn!("ORACLE_ADDRESS is missing; settlement is disabled");
    }
    let state = api::AppState::new(
        rpc,
        store,
        relayer,
        cfg.oracle_address,
        cfg.settler_max_fee_per_gas,
        cfg.receipt_timeout,
    );
    let recovery = state.spawn_recovery();
    let stop_recovery = recovery.as_ref().map(dcl_facilitator::recover::Handle::stopper);
    let addr = SocketAddr::new(cfg.host, cfg.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        %addr,
        rpc = cfg.base_rpc_url.is_some(),
        settler = cfg.settler_key_file.is_some(),
        recovery = recovery.is_some(),
        "listening"
    );

    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            if let Some(stop_recovery) = stop_recovery {
                stop_recovery();
            }
        })
        .await?;
    if let Some(recovery) = recovery {
        recovery.shutdown().await;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
