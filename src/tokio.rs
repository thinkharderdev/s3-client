use crate::client::HttpConfig;
use hyper::client::connect::{Connected, Connection};
use hyper::client::HttpConnector;
use hyper::{Client, Uri};
use hyper_tls::HttpsConnector;
use lazy_static::lazy_static;
use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};
use tower::Service;
use tracing::info;

lazy_static! {
    static ref IO_RUNTIME: Runtime = make_io_runtime();
}

fn make_io_runtime() -> Runtime {
    let cpus = num_cpus::get();

    info!("building tokio runtime with {cpus} worker threads");

    Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpus)
        .thread_name("s3-io-worker")
        .build()
        .unwrap()
}

#[derive(Clone)]
struct HyperExecutor;

impl<F> hyper::rt::Executor<F> for HyperExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        IO_RUNTIME.spawn(fut);
    }
}

#[derive(Clone)]
pub(crate) struct HyperConnector;

impl Service<Uri> for HyperConnector {
    type Response = HyperConnection;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let host = req.host().unwrap();
        let port = req.port_u16().unwrap_or(80);
        let address = format!("{host}:{port}");

        Box::pin(async move {
            let conn = TcpStream::connect(address).await?;

            let hyper_conn = HyperConnection(conn);
            Ok(hyper_conn)
        })
    }
}

pub(crate) struct HyperConnection(TcpStream);

impl AsyncRead for HyperConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for HyperConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for HyperConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

pub(crate) fn hyper_client(_config: HttpConfig) -> Client<HttpsConnector<HttpConnector>> {
    let https = HttpsConnector::new();
    Client::builder().executor(HyperExecutor).build(https)
}
