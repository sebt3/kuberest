#![allow(unused_imports, unused_variables)]
use actix_web::{get, middleware, web::Data, App, HttpRequest, HttpResponse, HttpServer, Responder};
pub use controller::{self, telemetry, State};
use prometheus::{Encoder, TextEncoder};
use std::env;

#[get("/metrics")]
async fn metrics(c: Data<State>, _req: HttpRequest) -> impl Responder {
    let metrics = c.metrics();
    let encoder = TextEncoder::new();
    let mut buffer = vec![];
    encoder.encode(&metrics, &mut buffer).unwrap();
    HttpResponse::Ok().body(buffer)
}

#[get("/health")]
async fn health(_: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json("healthy")
}

#[get("/")]
async fn index(c: Data<State>, _req: HttpRequest) -> impl Responder {
    let d = c.diagnostics().await;
    HttpResponse::Ok().json(&d)
}

static PORT_VAR_NAME: &str = "PORT";
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init().await;
    let port = if env::var(PORT_VAR_NAME).is_ok() {env::var(PORT_VAR_NAME).unwrap()} else {"8080".to_string()};

    // Initiatilize Kubernetes controller state
    let state = State::default();
    let controller = controller::run(state.clone());

    // Start web server
    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .wrap(middleware::Logger::default().exclude("/health"))
            .service(index)
            .service(health)
            .service(metrics)
    })
    .bind(format!("0.0.0.0:{port}"))?.shutdown_timeout(5);

    // Both runtimes implements graceful shutdown, so poll until both are done
    tokio::join!(controller, server.run()).1?;
    Ok(())
}
