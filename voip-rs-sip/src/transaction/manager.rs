use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc::{self};

use super::{Role, TransactionMessage};
use crate::message::HostPort;
use crate::transport::incoming::{IncomingInfo, IncomingRequest, IncomingResponse};
use crate::{Method, RFC3261_BRANCH_ID};

type TransactionChannel = mpsc::Sender<TransactionMessage>;

/// This type holds all server and client Transactions created by the TU (Transaction User).
#[derive(Default)]
pub struct TransactionManager {
    transactions: Mutex<HashMap<TransactionKey, TransactionChannel>>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add an transaction in the collection.
    #[inline]
    pub(crate) fn add_transaction(&self, key: TransactionKey, entry: TransactionChannel) {
        let mut map = self.transactions.lock().expect("Lock failed");

        map.insert(key, entry);
    }

    #[inline]
    pub(crate) fn remove(&self, key: &TransactionKey) {
        let mut map = self.transactions.lock().expect("Lock failed");

        map.remove(key);
    }

    #[inline]
    pub(crate) fn get_entry(&self, key: &TransactionKey) -> Option<TransactionChannel> {
        let map = self.transactions.lock().expect("Lock failed");

        map.get(key).cloned()
    }

    pub(crate) async fn handle_response(
        &self,
        response: IncomingResponse,
    ) -> Option<IncomingResponse> {
        let key = TransactionKey::from_response(&response);
        let Some(channel) = self.get_entry(&key) else {
            return Some(response);
        };
        let _res = channel.send(TransactionMessage::Response(response)).await;
        // let mandatory = &response.info.mandatory_headers;

        // let method = mandatory.cseq.method;
        // let Some(branch) = mandatory.via.branch.clone() else {
        //     return Some(response);
        // };
        // let key = TransactionKey::new_key_3261(Role::UAC, method, branch);
        // let map = self.transactions.lock().expect("Lock failed");
        // let Some(channel) = map.get(&key) else {
        //     return Some(response);
        // };
        // let _result = channel.send(TransactionMessage::Response(response));
        None
    }

    pub(crate) async fn receive(&self, request: IncomingRequest) -> Option<IncomingRequest> {
        let key = TransactionKey::from_request(&request);

        let Some(channel) = self.get_entry(&key) else {
            return Some(request);
        };
        let _res = channel.send(TransactionMessage::Request(request)).await;
        None
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum TransactionKey {
    Rfc2543(Rfc2543),
    Rfc3261(Rfc3261),
}

impl TransactionKey {
    pub fn from_request(request: &IncomingRequest) -> Self {
        Self::from_incoming_info(&request.incoming_info, Role::UAS)
    }

    pub fn from_response(response: &IncomingResponse) -> Self {
        Self::from_incoming_info(&response.incoming_info, Role::UAC)
    }

    fn from_incoming_info(info: &IncomingInfo, role: Role) -> Self {
        match info.mandatory_headers.via.branch {
            Some(ref branch) if branch.starts_with(RFC3261_BRANCH_ID) => {
                let branch = branch.clone();
                let method = info.mandatory_headers.cseq.method;

                Self::new_key_3261(role, method, branch)
            }
            _ => {
                todo!("create rfc 2543")
            }
        }
    }

    pub fn new_key_3261(role: Role, method: Method, branch: String) -> Self {
        let method = if matches!(method, Method::Invite | Method::Ack) {
            None
        } else {
            Some(method)
        };

        Self::Rfc3261(Rfc3261 {
            role,
            branch,
            method,
        })
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Rfc2543 {
    pub cseq: u32,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub call_id: String,
    pub via_host_port: HostPort,
    pub method: Option<Method>,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Rfc3261 {
    role: Role,
    branch: String,
    method: Option<Method>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint;
    use crate::message::Method;

    #[tokio::test]
    async fn test_non_invite_server_tsx() {
        /*
        let mut req = mock::request(Method::Register);

        let endpoint = endpoint::EndpointBuilder::new()
            .add_transaction(TransactionManager::default())
            .build();

        let tsx = endpoint.new_server_transaction(&mut req);

        let transactions = endpoint.transactions();
        let key = tsx.key();
        let tsx = transactions.find_server_tsx(&key);

        assert!(matches!(tsx.as_ref(), Some(ServerTransaction::NonInvite(_))));
        let tsx = match tsx.unwrap() {
            ServerTransaction::NonInvite(tsx) => tsx,
            _ => unreachable!(),
        };

        tsx.terminate();
        let tsx = transactions.find_server_tsx(&key);

        assert!(tsx.is_none());
         */
    }

    #[tokio::test]
    async fn test_invite_server_tsx() {
        /*
        let mut req = mock::request(Method::Invite);

        let endpoint = endpoint::EndpointBuilder::new()
            .add_transaction(TransactionManager::default())
            .build();

        let tsx = endpoint.new_inv_server_transaction(&mut req);

        let transactions = endpoint.transactions();
        let key = tsx.key();

        let tsx = transactions.find_server_tsx(&key);

        assert!(matches!(tsx.as_ref(), Some(ServerTransaction::Invite(_))));

        let tsx = match tsx.unwrap() {
            ServerTransaction::Invite(tsx) => tsx,
            _ => unreachable!(),
        };

        tsx.terminate();

        let tsx = transactions.find_server_tsx(&key);

        assert!(tsx.is_none());
        */
    }
}
