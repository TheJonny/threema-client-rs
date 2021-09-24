use tokio::sync::oneshot;
use tokio::sync::OnceCell;
use futures_core::stream::Stream;
use async_stream;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc,Weak};
use std::time::Duration;

use crate::{transport,Credentials,ThreemaID};
use crate::transport::{ThreemaServer, Envelope, Ack};

pub enum Event{
    Connected,
    Disconnected,
    BoxedMessage(transport::BoxedMessage),
    Alert(String),
    Error{reconnect_allowed: bool, message: String},
}

/// stuff that needs to be locked together to change it on reconnect.

pub struct Client {
    creds: Credentials,
    server: ThreemaServer,
    //last_sent_echo_seq: std::sync::atomic::AtomicU32,
    /// communicate pings from receive task to echo sender task
    last_rcvd_echo_seq: std::sync::atomic::AtomicU32,
    /// TODO: not usefull
    send_queue: tokio::sync::mpsc::UnboundedSender<((ThreemaID,u64), (Vec<u8>, oneshot::Sender<()>))>,

    keepalive_send_service: tokio::sync::Mutex<tokio::task::JoinHandle<()>>
    
}

impl Client {

    /*pub fn new(server: ThreemaServer, creds: Credentials){
        // start connection service
        let (send_queue,r) = tokio::sync::mpsc::unbounded_channel();
        let a = std::sync::Arc::new(
            Client{
                server, creds, send_queue,
                last_rcvd_echo_seq: 0.into(), last_sent_echo_seq: 0.into(), service: OnceCell::new(),
                ack_queue: Default::default(), con: Default::default()
            });
        let jh = tokio::task::spawn(Arc::clone(&a).run());
        
        a.service.set(jh);
        unimplemented!()
    } */
    /// Wait for next event
    pub async fn event(&self) -> Event {
        unimplemented!();
    }
    /// Upload message to the Server. When the function awaits the first time, the message is
    /// queued locally and will eventually be sent by the connection task.
    pub async fn send_message(&self, envelope: &Envelope, content: &[u8]) {
        // create oneshot
        // put message in send_queue

        // wait for oneshot
    }

    async fn keep_alive(self: Arc<Self>, event_queue: tokio::sync::mpsc::UnboundedSender<Event>) {
        const BACKOFF_MAX: Duration = Duration::from_secs(180);
        const BACKOFF_MIN: Duration = Duration::from_millis(50);
        const KEEP_ALIVE: Duration = Duration::from_secs(180);
        // ack_queue: Default::default()
        loop {
            let mut write_half;
            //let mut ack_queue;
            let mut recv_task;
            
            let mut backoff = BACKOFF_MIN;
            let last_rcvd_echo_seq = Arc::new(AtomicU32::new(0));
            let ack_queue: Arc<std::sync::Mutex<std::collections::HashMap<transport::Ack, (Vec<u8>, oneshot::Sender<()>)>>> = Arc::new(Default::default());
            loop {
                let res = transport::connect(&self.server, &self.creds).await;
                match res {
                    Ok((r,w)) => {
                        write_half = w;
                        recv_task = tokio::task::spawn(Self::receive_loop(r, event_queue.clone(), last_rcvd_echo_seq.clone(), ack_queue.clone()));
                        break;
                    }
                    Err(e) => {
                        log::warn!("Connection failed: {}, reconnecting in {}ms", e, backoff.as_millis());
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(BACKOFF_MAX, 2*backoff);
                    }
                }
            };
                // - connected event
            let _res = event_queue.send(Event::Connected);
            loop {
                tokio::select!{
                    a = &mut recv_task => {
                        // receive died -> reconnect
                        // flush ack queue to send queue
                        break; // this goes to the connect loop
                    }
                    a = tokio::time::sleep(KEEP_ALIVE / 2) => {
                        // check echo
                    }
                };
            }
            let _ = event_queue.send(Event::Disconnected);
                    //  - disconnect event
        }
    }

    async fn receive_loop(
            mut r: transport::ReadHalf,
            event_queue: tokio::sync::mpsc::UnboundedSender<Event>,
            last_received_echo: Arc<AtomicU32>,
            ack_queue: Arc<std::sync::Mutex<std::collections::HashMap<transport::Ack, (Vec<u8>, oneshot::Sender<()>)>>>,
            ) {
        loop {
            let res = r.receive_packet().await;
            match res {
                Ok(packet) => {
                    match packet {
                        transport::Packet::BoxedMessageDownload(m) => {
                            let _ = event_queue.send(Event::BoxedMessage(m));
                        }
                        transport::Packet::EchoReply(i) => {
                            last_received_echo.store(i, std::sync::atomic::Ordering::SeqCst);
                        }
                        transport::Packet::AckUpload(ack) =>{
                            let mut ack_queue_access = ack_queue.lock().unwrap();
                            if let Some((_, signal)) = ack_queue_access.remove(&ack) {
                                let _res = signal.send(());
                            }
                            drop(ack_queue_access);
                        }
                        unexpected => {
                            log::warn!("Received packet with unexpected payload type from server: {:?}", unexpected);
                        }
                    }
                }
                Err(_) => {
                    return;
                }
            }
        }
    }

}
