use downcast_rs::{Downcast, impl_downcast};
use utils::ToTake;

use crate::{
    Endpoint,
    transport::{
        incoming::{IncomingRequest, IncomingResponse},
        outgoing::{OutgoingRequest, OutgoingResponse},
    },
    endpoint::EndpointBuilder,
};

/// A trait for endpoint modules.
#[allow(unused)]
#[async_trait::async_trait]
pub trait Module: Downcast + Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn on_load(&mut self, builder: &mut EndpointBuilder) {}

    async fn on_receive_request(&self, request: ReceivedRequest<'_>, endpoint: &Endpoint) {}

    async fn on_receive_response(&self, response: ReceivedResponse<'_>, endpoint: &Endpoint) {}

    async fn on_send_request(&self, request: &mut OutgoingRequest) {}

    async fn on_send_response(&self, request: &mut OutgoingResponse) {}
}

impl_downcast!(Module);

pub struct ReceivedRequest<'r>(ToTake<'r, IncomingRequest>);

impl<'r> ReceivedRequest<'r> {
    pub(crate) fn new(request: ToTake<'r, IncomingRequest>) -> Self {
        Self(request)
    }
}

impl<'r> std::ops::Deref for ReceivedRequest<'r> {
    type Target = ToTake<'r, IncomingRequest>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> std::ops::DerefMut for ReceivedRequest<'r> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct ReceivedResponse<'r>(ToTake<'r, IncomingResponse>);

impl<'r> ReceivedResponse<'r> {
    pub(crate) fn new(response: ToTake<'r, IncomingResponse>) -> Self {
        Self(response)
    }
}

impl<'r> std::ops::Deref for ReceivedResponse<'r> {
    type Target = ToTake<'r, IncomingResponse>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> std::ops::DerefMut for ReceivedResponse<'r> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Default)]
pub struct Modules {
    modules: Vec<Box<dyn Module>>,
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
