use std::collections::HashMap;
use std::sync::Mutex;

pub(crate) mod dialog;
pub mod session;

use dialog::{Dialog, DialogId, DialogMessage};
use tokio::sync::mpsc;

use crate::error::DialogError;
use crate::message::Scheme;
use crate::message::headers::Contact;
use crate::transaction::Role;
use crate::transport::incoming::IncomingRequest;
use crate::transport::outgoing::OutgoingResponse;
use crate::ua::dialog::DialogState;
use crate::{Endpoint, Method, Result};

/// Returns `true` if this method can establish a dialog
const fn can_establish_a_dialog(method: &Method) -> bool {
    matches!(method, Method::Invite)
}

pub struct UA {
    dialogs: Mutex<HashMap<DialogId, mpsc::Sender<DialogMessage>>>,
}

impl UA {
    pub fn new() -> Self {
        Self {
            dialogs: Default::default(),
        }
    }

    pub async fn handle_request(&self, request: IncomingRequest) -> Option<IncomingRequest> {
        if request.req_line.method == Method::Cancel {
            return Some(request);
        }
        let Some(sender) = self.get_dialog(&request) else {
            return Some(request);
        };
        sender.send(DialogMessage::Request(request)).await.unwrap();
        None
    }

    pub(crate) fn register_dialog(&self, dialog_id: DialogId, dialog: mpsc::Sender<DialogMessage>) {
        let mut dialogs = self.dialogs.lock().expect("Lock failed");

        dialogs.insert(dialog_id, dialog);
    }

    fn get_dialog(&self, request: &IncomingRequest) -> Option<mpsc::Sender<DialogMessage>> {
        let Some(dialog_id) = DialogId::from_incoming_request(request) else {
            return None;
        };
        let dialogs = self.dialogs.lock().expect("Lock failed");

        dialogs.get(&dialog_id).cloned()
    }
}
