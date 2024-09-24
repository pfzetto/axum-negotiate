use axum::{error_handling::HandleErrorLayer, response::IntoResponse, routing::get, Router};
use axum_negotiate::{NegotiateAuthLayer, Upn};
use log::warn;
use tokio::net::TcpListener;
use tower::ServiceBuilder;

#[tokio::main]
async fn main() {
    env_logger::init();

    let spn = "HTTP/webserver.example.com";

    let auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|e: axum_negotiate::Error| async {
            warn!("{}", e);
            e.into_response()
        }))
        .layer(NegotiateAuthLayer::new(spn.to_owned()).unwrap());

    let app = Router::new()
        .route("/", get(hello_world))
        .route_layer(auth_service);

    let listener = TcpListener::bind("[::]:8080").await.unwrap();

    axum::serve(listener, app).await.unwrap()
}

async fn hello_world(Upn(upn): Upn) -> impl IntoResponse {
    format!("Hello {}", upn)
}
