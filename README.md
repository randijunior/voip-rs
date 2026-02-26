# voip

This project is in its early stages of development.

# Usage

```rust
use voip::sip::endpoint::{Module as EndpointModule, Endpoint, ReceivedRequest};
use voip::sip::message::{Method, StatusCode};


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut builder = Endpoint::builder();
    builder.add_module(SipStateless);

    let endpoint = builder.build();
    endpoint.start_udp_transport("0.0.0.0:8089").await?;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

pub struct SipStateless;

#[async_trait::async_trait]
impl EndpointModule for SipStateless {
    fn name(&self) -> &'static str {
        "sip-stateless"
    }

    async fn on_receive_request(&self, mut received: ReceivedRequest<'_>, endpoint: &Endpoint) {
        let request = received.take();

        if request.req_line.method != Method::Ack {
            endpoint.respond(&request, StatusCode::NotImplemented, None).await.unwrap();
        }
    }
}
```