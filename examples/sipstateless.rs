use std::error::Error;

use tracing::Level;
use tracing_subscriber::fmt::time::ChronoLocal;
use voip::sip::endpoint::{
    Endpoint, EndpointTransports, Module as EndpointModule, ReceivedRequest,
};
use voip::sip::message::{Method, StatusCode};

pub struct SipStateless;

#[async_trait::async_trait]
impl EndpointModule for SipStateless {
    fn name(&self) -> &'static str {
        "sip-stateless"
    }

    async fn on_receive_request(&self, mut received: ReceivedRequest<'_>, endpoint: &Endpoint) {
        let request = received.take();

        if request.req_line.method != Method::Ack {
            endpoint
                .respond(&request, StatusCode::NotImplemented, None)
                .await
                .unwrap();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_env_filter("voip=trace")
        .with_timer(ChronoLocal::new(String::from("%H:%M:%S%.3f")))
        .init();

    let mut transports = EndpointTransports::default();

    transports.add_udp("0.0.0.0:8089")?;

    let endpoint = Endpoint::builder()
        .with_transports(transports)
        .with_module(SipStateless)
        .build()
        .await?;

    endpoint.run_forever().await?;

    Ok(())
}
