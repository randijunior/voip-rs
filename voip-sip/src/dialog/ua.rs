use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;


use crate::dialog::{DialogId, DialogMessage};
use crate::transport::incoming::{IncomingRequest};

use crate::endpoint::{self, ReceivedResponse};
use crate::endpoint::ReceivedRequest;
use crate::{Endpoint, Method};


#[derive(Default)]
pub struct UaModule {
    dialogs: Mutex<HashMap<DialogId, mpsc::Sender<DialogMessage>>>,
}

impl UaModule {
    pub fn new() -> Self {
        Self::default()
    }

    // pub async fn handle_response(&self, response: IncomingResponse) -> Option<IncomingResponse> {
    //     let Some(sender) = self.get_dialog_from_response(&response) else {
    //         return Some(response);
    //     };
    //     log::debug!("FOUND DIALOG FROM RESPONSE!");
    //     sender.send(DialogMessage::Response(response)).await.unwrap();
    //     None
    // }

    pub(crate) fn register_dialog(&self, dialog_id: DialogId, dialog: mpsc::Sender<DialogMessage>) {
        let mut dialogs = self.dialogs.lock().expect("Lock failed");

        dialogs.insert(dialog_id, dialog);
    }

    pub(crate) fn remove_dialog(&self, dialog_id: &DialogId) {
        let mut dialogs = self.dialogs.lock().expect("Lock failed");

        dialogs.remove(&dialog_id);
    }

    // fn get_dialog_from_response(&self, response: &IncomingResponse) -> Option<mpsc::Sender<DialogMessage>> {
    //     let Some(dialog_id) = DialogId::from_incoming_response(response) else {
    //         return None;
    //     };
    //     let dialogs = self.dialogs.lock().expect("Lock failed");

    //     dialogs.get(&dialog_id).cloned()
    // }

    pub(crate) fn get_dialog_from_request(
        &self,
        request: &IncomingRequest,
    ) -> Option<mpsc::Sender<DialogMessage>> {
        let Some(dialog_id) = DialogId::from_incoming_request(request) else {
            return None;
        };
        let dialogs = self.dialogs.lock().expect("Lock failed");

        dialogs.get(&dialog_id).cloned()
    }
}

#[async_trait::async_trait]
impl endpoint::Module for UaModule {
    fn name(&self) -> &'static str {
        "dialog-module"
    }

    async fn on_receive_request(&self, mut request: ReceivedRequest<'_>, _: &Endpoint) {
        if request.req_line.method == Method::Cancel {
            return;
        }

        let Some(sender) = self.get_dialog_from_request(&request) else {
            return;
        };
        
        let req = request.take();

        if sender.send(DialogMessage::Request(req)).await.is_err() {
            log::error!("failed to send message to dialog!");
        }
    }

    async fn on_receive_response(&self, response: ReceivedResponse<'_>, endpoint: &Endpoint) {}
}