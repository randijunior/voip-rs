use std::sync::Arc;

use utils::DnsResolver;

use super::{Endpoint, EndpointHandler};
use crate::endpoint::EndpointInner;
use crate::message::headers::{Header, Headers};
use crate::transaction::manager::TransactionManager;
use crate::transport::TransportManager;
use crate::ua::UA;

/// EndpointBuilder for creating a new SIP `Endpoint`.
pub struct EndpointBuilder {
    name: String,
    resolver: DnsResolver,
    transaction: Option<TransactionManager>,
    transports: Option<TransportManager>,
    capabilities: Headers,
    handler: Option<Box<dyn EndpointHandler>>,
    user_agent: Option<UA>,
}

impl EndpointBuilder {
    /// Creates a new default instance of `EndpointBuilder` to
    /// construct a `Endpoint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip::*;
    /// let endpoint = endpoint::EndpointBuilder::new()
    ///     .with_name("My Endpoint")
    ///     .build();
    /// ```
    pub fn new() -> Self {
        EndpointBuilder {
            name: String::new(),
            capabilities: Headers::new(),
            resolver: DnsResolver::default(),
            handler: None,
            transaction: None,
            transports: Default::default(),
            user_agent: None,
        }
    }

    /// Sets the endpoint name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip::*;
    /// let endpoint = endpoint::EndpointBuilder::new()
    ///     .with_name("My Endpoint")
    ///     .build();
    /// ```
    pub fn with_name<T: AsRef<str>>(mut self, s: T) -> Self {
        self.name = s.as_ref().to_string();

        self
    }

    /// Add a new capability to the endpoint.
    pub fn with_capability(mut self, capability: Header) -> Self {
        self.capabilities.push(capability);

        self
    }

    /// Adds a service to the endpoint.
    ///
    /// This function can be called multiple times to add
    /// additional handlers. If a service with the same
    /// name already exists, the new service will not be
    /// added.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip::*;
    /// struct MyService;
    ///
    /// impl EndpointHandler for MyService {
    ///     fn name(&self) -> &str {
    ///         "MyService"
    ///     }
    /// }
    /// let endpoint = endpoint::EndpointBuilder::new()
    ///     .with_service(MyService)
    ///     .build();
    /// ```
    pub fn with_handler(mut self, service: impl EndpointHandler) -> Self {
        self.handler = Some(Box::new(service));

        self
    }

    /// Sets the transaction layer.
    pub fn with_transaction(mut self, tsx_layer: TransactionManager) -> Self {
        self.transaction = Some(tsx_layer);

        self
    }

    /// Sets the transaction layer.
    pub fn with_ua(mut self, ua: UA) -> Self {
        self.user_agent = Some(ua);

        self
    }

    /// Sets the transport layer.
    pub fn with_transport(mut self, transport: TransportManager) -> Self {
        self.transports = Some(transport);

        self
    }

    /// Finalize the EndpointBuilder into a `Endpoint`.
    pub fn build(self) -> Endpoint {
        log::trace!("Creating endpoint...");
        // log::debug!(
        //     "Handler registered {}",
        //     format_args!("({})", self.handler.and_then(|h| h.name()).unwrap_or(""))
        // );

        let endpoint = Endpoint {
            inner: Arc::new(EndpointInner {
                transaction: self.transaction,
                transport: self.transports.unwrap_or(TransportManager::new()),
                name: self.name,
                capabilities: self.capabilities,
                resolver: self.resolver,
                handler: self.handler,
                user_agent: self.user_agent,
            }),
        };

        endpoint
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}
