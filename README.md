# voip

This project is in its early stages of development.

# Usage

```rust
use std::error::Error;

use voip::sip::endpoint::{Endpoint, Module as EndpointModule, ReceivedRequest, EndpointTransports};
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
    let mut transports = EndpointTransports::default();

    transports.add_udp("0.0.0.0:8089")?;

    let endpoint = Endpoint::builder()
        .with_transports(transports)
        .with_module(SipStateless)
        .build().await?;

    endpoint.run_forever().await?;

    Ok(())
}
```