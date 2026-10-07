//! axum binding (feature `http`) for the MS-WSUSSS upstream server.
//!
//! Reuses the MS-WUSP binding's adapter ([`super::super::http::HttpService`]): the same
//! body cap, blocking boundary and streamed content bodies. A downstream server reaches the
//! web services and the content directory on different ports (see
//! [`super::server_server_content_port`]), so [`serve`] takes two listeners and restricts
//! each to its [`Surface`]. [`serve_combined`] shares one listener with the MS-WUSP server.
//!
//! Plain HTTP only; terminate TLS in front of the listener.
use axum::Router;

use super::super::http::{HttpService, router as service_router};
use super::super::{HttpRequestParts, HttpResponseParts, WsusServer};
use super::{Surface, UpstreamServer};

/// An [`UpstreamServer`] bound to one [`Surface`].
#[derive(Clone)]
pub struct UpstreamHttp {
    server: UpstreamServer,
    surface: Surface,
}

impl UpstreamHttp {
    pub fn new(server: UpstreamServer, surface: Surface) -> Self {
        Self { server, surface }
    }
}

impl HttpService for UpstreamHttp {
    fn max_request_bytes(&self) -> usize {
        self.server.config().max_request_bytes
    }
    fn handle(&self, req: HttpRequestParts) -> HttpResponseParts {
        self.server.handle_on(self.surface, req)
    }
    fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts {
        self.server.too_large(req)
    }
    fn internal_error(&self) -> HttpResponseParts {
        self.server.internal_error()
    }
}

/// One listener for the MS-WUSP server and the MS-WSUSSS upstream server: SOAP paths of the
/// upstream server go to it, everything else (including `/Content/`) to the MS-WUSP server,
/// which serves the same content store.
#[derive(Clone)]
pub struct Combined {
    pub wusp: WsusServer,
    pub upstream: UpstreamServer,
}

impl HttpService for Combined {
    fn max_request_bytes(&self) -> usize {
        self.wusp
            .config()
            .max_request_bytes
            .max(self.upstream.config().max_request_bytes)
    }
    fn handle(&self, req: HttpRequestParts) -> HttpResponseParts {
        if self.upstream.owns_path(&req.path) {
            self.upstream.handle_on(Surface::Services, req)
        } else {
            self.wusp.handle(req)
        }
    }
    fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts {
        self.upstream.too_large(req)
    }
    fn internal_error(&self) -> HttpResponseParts {
        self.upstream.internal_error()
    }
}

/// Router for one surface.
pub fn router(server: UpstreamServer, surface: Surface) -> Router {
    service_router(UpstreamHttp::new(server, surface))
}

/// Serve the web services on `services` and the content directory on `content` until the
/// future is dropped. Pass the same port for both only through [`serve_one`].
pub async fn serve(
    services: tokio::net::TcpListener,
    content: tokio::net::TcpListener,
    server: UpstreamServer,
) -> std::io::Result<()> {
    let a = std::future::IntoFuture::into_future(axum::serve(
        services,
        router(server.clone(), Surface::Services),
    ));
    let b = std::future::IntoFuture::into_future(axum::serve(
        content,
        router(server, Surface::Content),
    ));
    futures_util::future::try_join(a, b).await.map(|_| ())
}

/// Serve everything on one listener.
pub async fn serve_one(
    listener: tokio::net::TcpListener,
    server: UpstreamServer,
) -> std::io::Result<()> {
    axum::serve(listener, router(server, Surface::All)).await
}

/// Serve the MS-WUSP and MS-WSUSSS servers on one listener.
pub async fn serve_combined(
    listener: tokio::net::TcpListener,
    wusp: WsusServer,
    upstream: UpstreamServer,
) -> std::io::Result<()> {
    axum::serve(listener, service_router(Combined { wusp, upstream })).await
}
