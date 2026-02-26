use std::sync::Arc;

use utils::DnsResolver;

use crate::message::headers::{Accept, Allow, Headers};

use crate::transport::TransportModule;

use crate::{Endpoint, MediaType, Method};
use crate::endpoint::{EndpointInner};
use crate::endpoint::module::{Module, Modules};


/// EndpointBuilder for creating a new SIP `Endpoint`.
pub struct EndpointBuilder {
    name: String,
    resolver: DnsResolver,
    modules: Modules,
    allow: Allow,
    accept: Accept
}

impl EndpointBuilder {
    pub fn new() -> Self {
        EndpointBuilder {
            name: String::new(),
            resolver: DnsResolver::default(),
            modules: Modules::default(),
            accept: Accept::new(),
            allow: Allow::new()
        }
    }

    /// Sets the endpoint name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip::*;
    /// let endpoint = endpoint::EndpointBuilder::new()
    ///     .add_name("My Endpoint")
    ///     .build();
    /// ```
    pub fn add_name<T: AsRef<str>>(&mut self, s: T) -> &mut Self {
        self.name = s.as_ref().to_string();

        self
    }

    pub fn add_module<M: Module>(&mut self, module: M) -> &mut Self {
        self.modules.add_module(module);

        self
    }

    pub fn add_allow(&mut self, sip_method: Method) -> &mut Self {
        self.allow.push(sip_method);
        self
    }

    pub fn add_accept(&mut self, media_type: MediaType) -> &mut Self {
        self.accept.push(media_type);
        self
    }

    /// Finalize the EndpointBuilder into a `Endpoint`.
    pub fn build(mut self) -> Endpoint {
        log::trace!("Creating endpoint...");

        let mut modules = std::mem::take(&mut self.modules);

        for module in modules.iter_mut() {
            module.on_load(&mut self);
            log::debug!("Module {} loaded", format_args!("({})", module.name()));
        }

        let endpoint = Endpoint {
            inner: Arc::new(EndpointInner {
                transport: TransportModule::new(),
                name: self.name,
                capabilities: Headers::new(),
                resolver: self.resolver,
                modules: modules,
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
