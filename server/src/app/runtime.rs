use crate::config::{ServerConfig, ServerTlsConfig};
use anyhow::{bail, Context};
use axum::{body::Body, http::Request, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{Certificate, PrivateKey};
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::util::ServiceExt as _;
use tracing::{error, info};

pub async fn serve_router(router: Router, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    let public_addr: SocketAddr = config.bind.parse()?;
    let local_addr = parse_optional_bind(config.local_bind.as_deref())?;

    if let Some(local_addr) = local_addr {
        if listener_addresses_conflict(public_addr, local_addr) {
            bail!(
                "local_bind {} conflicts with bind {}. Use a different port for the loopback-only listener.",
                local_addr,
                public_addr
            );
        }
    }

    let tls_config = config
        .tls_config()?
        .map(|tls_files| load_tls_server_config(&tls_files))
        .transpose()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut listeners = JoinSet::new();

    if let Some(local_addr) = local_addr {
        info!("Local plain HTTP listener enabled on {}", local_addr);
        listeners.spawn(run_http_listener(
            local_addr,
            router.clone(),
            shutdown_rx.clone(),
        ));
    }

    if let Some(tls_config) = tls_config {
        info!("Native TLS API listener enabled on https://{}", public_addr);
        listeners.spawn(run_https_listener(
            public_addr,
            router,
            tls_config,
            shutdown_rx.clone(),
        ));
    } else {
        info!("Plain HTTP listener enabled on http://{}", public_addr);
        listeners.spawn(run_http_listener(public_addr, router, shutdown_rx.clone()));
    }

    let mut shutdown_error = tokio::select! {
        signal = shutdown_signal() => {
            info!("Shutdown signal received ({}), stopping listeners...", signal);
            None
        }
        result = listeners.join_next() => {
            match result {
                Some(Ok(Ok(()))) => Some(anyhow::anyhow!("listener task exited unexpectedly")),
                Some(Ok(Err(err))) => Some(err),
                Some(Err(err)) => Some(anyhow::Error::new(err).context("listener task failed")),
                None => Some(anyhow::anyhow!("no listeners were started")),
            }
        }
    };

    let _ = shutdown_tx.send(true);

    while let Some(result) = listeners.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if shutdown_error.is_none() {
                    shutdown_error = Some(err);
                }
            }
            Err(err) => {
                if shutdown_error.is_none() {
                    shutdown_error = Some(anyhow::Error::new(err).context("listener task failed"));
                }
            }
        }
    }

    if let Some(err) = shutdown_error {
        return Err(err);
    }

    Ok(())
}

async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        "CTRL+C"
    }
}

async fn run_http_listener(
    bind: SocketAddr,
    router: Router,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {}", bind))?;

    axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
        .with_context(|| format!("HTTP listener on {} failed", bind))?;

    Ok(())
}

async fn run_https_listener(
    bind: SocketAddr,
    router: Router,
    tls_config: Arc<rustls::ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind HTTPS listener on {}", bind))?;
    let acceptor = TlsAcceptor::from(tls_config);

    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = accept_connection(&listener) => accepted,
        };

        let Some((tcp_stream, remote_addr)) = accepted else {
            continue;
        };

        let acceptor = acceptor.clone();
        let service = router.clone().into_service::<Body>();
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let hyper_service = TowerToHyperService::new(
                        service.map_request(|req: Request<Incoming>| req.map(Body::new)),
                    );

                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(tls_stream), hyper_service)
                        .await
                    {
                        error!("HTTPS connection {} failed: {}", remote_addr, err);
                    }
                }
                Err(err) => {
                    error!("TLS handshake failed for {}: {}", remote_addr, err);
                }
            }
        });
    }

    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.changed().await;
}

async fn accept_connection(listener: &TcpListener) -> Option<(tokio::net::TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(conn) => Some(conn),
        Err(err) => {
            if is_connection_error(&err) {
                return None;
            }

            error!("accept error: {}", err);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            None
        }
    }
}

fn is_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

pub fn parse_optional_bind(bind: Option<&str>) -> anyhow::Result<Option<SocketAddr>> {
    bind.filter(|value| !value.trim().is_empty())
        .map(|value| value.parse().context("invalid local_bind"))
        .transpose()
}

pub fn listener_addresses_conflict(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

fn load_tls_server_config(
    tls_files: &ServerTlsConfig,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = load_certificates(&tls_files.cert_path)?;
    let key = load_private_key(&tls_files.key_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build rustls server config")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(tls_config))
}

fn load_certificates(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let file = File::open(path).with_context(|| format!("failed to open TLS cert {}", path))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).context("failed to parse TLS certificate")?;

    if certs.is_empty() {
        bail!("no certificates found in {}", path);
    }

    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &str) -> anyhow::Result<PrivateKey> {
    let file = File::open(path).with_context(|| format!("failed to open TLS key {}", path))?;
    let mut reader = BufReader::new(file);

    let mut pkcs8_keys =
        rustls_pemfile::pkcs8_private_keys(&mut reader).context("failed to parse PKCS#8 key")?;
    if let Some(key) = pkcs8_keys.pop() {
        return Ok(PrivateKey(key));
    }

    let file = File::open(path).with_context(|| format!("failed to reopen TLS key {}", path))?;
    let mut reader = BufReader::new(file);
    let mut rsa_keys =
        rustls_pemfile::rsa_private_keys(&mut reader).context("failed to parse RSA key")?;
    if let Some(key) = rsa_keys.pop() {
        return Ok(PrivateKey(key));
    }

    bail!("no supported private key found in {}", path)
}
