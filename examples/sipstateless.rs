use std::error::Error;

use async_trait::async_trait;
use csip::message::{Method, StatusCode};
use csip::transport::incoming::IncomingRequest;
use csip::{Endpoint, EndpointHandler};
use tracing::Level;
use tracing_subscriber::fmt::time::ChronoLocal;

pub struct StatelessUAS;

#[async_trait]
impl EndpointHandler for StatelessUAS {
    async fn handle(&self, request: IncomingRequest, endpoint: &Endpoint) {
        if request.req_line.method != Method::Ack {
            let mut response = endpoint.create_response(&request, StatusCode::NotImplemented, None);

            endpoint
                .send_outgoing_response(&mut response)
                .await
                .unwrap();
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_env_filter("csip=trace")
        .with_timer(ChronoLocal::new(String::from("%H:%M:%S%.3f")))
        .init();

    let svc = StatelessUAS;
    let addr = "127.0.0.1:0".parse()?;

    let endpoint = Endpoint::builder().with_handler(svc).build();

    endpoint.start_ws_transport(addr).await?;
    endpoint.start_udp_transport(addr).await?;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
