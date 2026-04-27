use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::protocol::SessionId;
use crate::swarm::SwarmRuntime;

#[derive(Debug)]
pub struct SwarmSchedulerHandle {
    stop: Option<Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl SwarmSchedulerHandle {
    pub fn start(runtime: SwarmRuntime, session_id: SessionId, interval: Duration) -> Self {
        let _ = runtime.tick_session(&session_id);

        let (stop, stop_rx) = mpsc::channel();
        let join = thread::spawn(move || loop {
            match stop_rx.recv_timeout(interval) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    let _ = runtime.tick_session(&session_id);
                }
            }
        });

        Self {
            stop: Some(stop),
            join: Some(join),
        }
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for SwarmSchedulerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}
