use crate::{
    Endpoint, Result,
    message::{StatusCode, headers::Contact},
    transaction::ServerTransaction,
    transport::incoming::IncomingRequest,
    ua::dialog::{Dialog, DialogState},
};

pub struct UasInvSession<State> {
    state: State,
}

struct Initial {
    invite: IncomingRequest,
    contact: Contact,
    endpoint: Endpoint,
}

impl UasInvSession<Initial> {
    pub fn new(endpoint: Endpoint, invite: IncomingRequest, contact: Contact) -> Self {
        Self {
            state: Initial {
                invite,
                contact,
                endpoint,
            },
        }
    }

    pub async fn progress(self, code: StatusCode) -> Result<UasInvSession<Early>> {
        let Initial {
            invite,
            contact,
            endpoint,
        } = self.state;

        let mut dialog = Dialog::new_uas(&invite, contact, endpoint.clone())?;
        let mut server_tsx = ServerTransaction::new(invite, endpoint);

        server_tsx.send_provisional_status(code).await?;

        dialog.set_state(DialogState::Early);

        let state = Early { dialog, server_tsx };

        Ok(UasInvSession { state })
    }

    pub async fn accept(mut self, code: StatusCode) -> Result<UasInvSession<Completed>> {
        unimplemented!()
    }

    pub async fn redirect(&mut self, code: StatusCode) -> Result<()> {
        unimplemented!()
    }

    pub async fn reject(&mut self, code: StatusCode) -> Result<()> {
        unimplemented!()
    }
}

struct Early {
    dialog: Dialog,
    server_tsx: ServerTransaction,
}

struct Completed {}

struct Confirmed {}

impl UasInvSession<Early> {
    pub async fn progress(&mut self, code: StatusCode) -> Result<()> {
        self.state.server_tsx.send_provisional_status(code).await?;
        Ok(())
    }
    pub async fn accept(mut self, code: StatusCode) -> Result<UasInvSession<Completed>> {
        unimplemented!()
    }
    pub async fn redirect(&mut self, code: StatusCode) -> Result<()> {
        unimplemented!()
    }

    pub async fn reject(&mut self, code: StatusCode) -> Result<()> {
        unimplemented!()
    }
}

impl UasInvSession<Completed> {
    pub async fn wait_ack(mut self) -> Result<UasInvSession<Confirmed>> {
        unimplemented!()
    }
}

