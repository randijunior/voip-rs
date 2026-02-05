use std::collections::HashMap;
use std::sync::Mutex;

pub(crate) mod dialog;
pub mod session;

use tokio::sync::mpsc;

use dialog::{Dialog, DialogId, DialogMessage};

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

    pub(crate) fn create_uas_dialog(
        &self,
        request: &IncomingRequest,
        contact: Contact,
        endpoint: Endpoint
    ) -> Result<Dialog> {
        if !can_establish_a_dialog(&request.req_line.method) {
            return Err(DialogError::InvalidMethod.into());
        }
        let mandatory_headers = &request.incoming_info.mandatory_headers;
    
        let Some(local_tag) = mandatory_headers.to.tag().clone() else {
            return Err(DialogError::MissingTagInToHeader.into());
        };
    
        let to = mandatory_headers.to.clone();
        let from = mandatory_headers.from.clone();
    
        let remote_cseq = mandatory_headers.cseq.cseq;
        let local_seq_num = None;
    
        let route_set = dialog::RouteSet::from_headers(&request.request.headers);
        let secure = request.incoming_info.transport.transport.is_secure()
            && request.request.req_line.uri.scheme == Scheme::Sips;
    
        let dialog_id = DialogId {
            call_id: mandatory_headers.call_id.clone(),
            remote_tag: from.tag().clone().unwrap_or_default(),
            local_tag,
        };
    
        let (sender, receiver) = mpsc::channel(10);
    
        self.register_dialog(dialog_id.clone(), sender);
    
        let dialog = Dialog::new(
            endpoint,
            dialog_id,
            DialogState::Initial,
            remote_cseq,
            local_seq_num,
            from,
            to,
            contact,
            secure,
            route_set,
            Vec::new(),
            receiver,
            Role::UAS,
        );
    
        Ok(dialog)
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