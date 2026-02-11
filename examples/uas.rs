use std::error::Error;
use std::time::Duration;

use async_trait::async_trait;
use voip::sip::message::{Method, StatusCode};
use voip::sip::transaction::TransactionManager;
use voip::sip::transport::incoming::IncomingRequest;
use voip::sip::{Endpoint, EndpointHandler};
use tokio::time;
use tracing::Level;

pub struct UAS;

#[async_trait]
impl EndpointHandler for UAS {
    async fn handle(&self, request: IncomingRequest, endpoint: &Endpoint) {
        if request.req_line.method == Method::Options {
            let uas = endpoint.new_server_transaction(request);

            let _res = uas.send_final_status(StatusCode::Ok).await;
            return;
        }
        if request.req_line.method != Method::Ack {
            let mut response = endpoint.create_response(&request, StatusCode::NotImplemented, None);
            endpoint
                .send_outgoing_response(&mut response)
                .await
                .unwrap();
            return;
        }

        tracing::debug!("Received ACK request, no response needed.");
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_env_filter("voip=trace")
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .init();

    let addr = "127.0.0.1:0".parse()?;

    let endpoint = Endpoint::builder()
        .with_handler(UAS)
        .with_transaction(TransactionManager::new())
        .build();

    endpoint.start_tcp_transport(addr).await?;
    endpoint.start_udp_transport(addr).await?;
    endpoint.start_ws_transport(addr).await?;

    loop {
        tokio::select! {
            _ = time::sleep(Duration::from_secs(1)) => {
            }
            _ = tokio::signal::ctrl_c() => {
            println!();
            break;
        }
        }
    }
    Ok(())
}
