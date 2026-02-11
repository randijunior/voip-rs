use tokio::sync::watch;

/// Defines the possible states of a SIP Transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum State {
    #[default]
    /// Initial state
    Initial,
    /// Calling state
    Calling,
    /// Trying state
    Trying,
    /// Proceeding state
    Proceeding,
    /// Completed state
    Completed,
    /// Confirmed state
    Confirmed,
    /// Terminated state
    Terminated,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            Self::Initial => "Initial",
            Self::Calling => "Calling",
            Self::Trying => "Trying",
            Self::Proceeding => "Proceeding",
            Self::Completed => "Completed",
            Self::Confirmed => "Confirmed",
            Self::Terminated => "Terminated",
        };
        write!(f, "{}", state_str)
    }
}

pub struct StateMachine {
    state: State,
    state_change_notifier: Option<watch::Sender<State>>,
}

impl StateMachine {
    pub fn new(state: State) -> Self {
        Self {
            state,
            state_change_notifier: None,
        }
    }
    /// Subscribe to transaction state changes
    ///
    /// Returns a watch::Receiver that can be used to monitor state changes
    pub fn subscribe_state(&mut self) -> watch::Receiver<State> {
        match self.state_change_notifier {
            Some(ref state) => state.subscribe(),
            None => {
                let (sender, recv) = watch::channel(self.state);

                self.state_change_notifier = Some(sender);

                recv
            }
        }
    }

    #[inline(always)]
    fn borrow_state_notifier(&self) -> Option<&watch::Sender<State>> {
        self.state_change_notifier.as_ref()
    }

    #[inline(always)]
    fn notify_state_change(&self, state: State) {
        if let Some(sender) = self.borrow_state_notifier() {
            let _result = sender.send(state);
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn set_state(&mut self, state: State) {
        self.state = state;

        self.notify_state_change(state);
    }
}
