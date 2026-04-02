use std::ops;

use downcast_rs::{Downcast, impl_downcast};

use crate::Endpoint;
use crate::endpoint::EndpointBuilder;
use crate::transport::incoming::{IncomingRequest, IncomingResponse};
use crate::transport::outgoing::{OutgoingRequest, OutgoingResponse};

/// A trait for endpoint module.
#[async_trait::async_trait]
pub trait Module: Downcast + Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn on_load(&mut self, _builder: &mut EndpointBuilder) {}

    async fn on_receive_request(&self, _request: ReceivedRequest<'_>, _endpoint: &Endpoint) {}

    async fn on_receive_response(&self, _response: ReceivedResponse<'_>, _endpoint: &Endpoint) {}

    async fn on_send_request(&self, _request: &mut OutgoingRequest) {}

    async fn on_send_response(&self, _request: &mut OutgoingResponse) {}
}

impl_downcast!(Module);

#[derive(Default)]
pub struct Modules {
    modules: Vec<Box<dyn Module>>,
}

pub struct ReceivedRequest<'r>(ToTake<'r, IncomingRequest>);

pub struct ReceivedResponse<'r>(ToTake<'r, IncomingResponse>);

pub struct ToTake<'a, T: 'a> {
    inner: &'a mut Option<T>,
}

impl Modules {
    pub fn modules(&self) -> &Vec<Box<dyn Module>> {
        &self.modules
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Box<dyn Module + 'static>> {
        self.modules.iter_mut()
    }

    pub fn find_module<M: Module>(&self) -> Option<&M> {
        self.modules.iter().find_map(|m| m.downcast_ref())
    }

    pub fn add_module<M: Module>(&mut self, module: M) {
        self.modules.push(Box::new(module));
    }
}

impl<'r> ReceivedRequest<'r> {
    pub(crate) fn new(request: &'r mut Option<IncomingRequest>) -> Self {
        Self(ToTake::new(request))
    }
}

impl<'r> ops::Deref for ReceivedRequest<'r> {
    type Target = ToTake<'r, IncomingRequest>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> ops::DerefMut for ReceivedRequest<'r> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'r> ReceivedResponse<'r> {
    pub(crate) fn new(response: &'r mut Option<IncomingResponse>) -> Self {
        Self(ToTake::new(response))
    }
}

impl<'r> ops::Deref for ReceivedResponse<'r> {
    type Target = ToTake<'r, IncomingResponse>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> ops::DerefMut for ReceivedResponse<'r> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, T: 'a> ToTake<'a, T> {
    #[must_use]
    pub const fn new(inner: &'a mut Option<T>) -> Self {
        assert!(inner.is_some());

        Self { inner }
    }

    pub fn take(&'a mut self) -> T {
        self.inner.take().unwrap()
    }
}

impl<'a, T> ops::Deref for ToTake<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner.as_ref().unwrap()
    }
}

impl<'a, T> ops::DerefMut for ToTake<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner.as_mut().unwrap()
    }
}
