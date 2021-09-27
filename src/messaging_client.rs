/// At the moment, this does not do anything usefull

use tokio::sync::oneshot;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use crate::{transport,Credentials};
use crate::transport::{ThreemaServer, Ack, BoxedMessage};

#[derive(Clone, Debug)]
pub enum Event{
    Connected,
    Disconnected,
    BoxedMessage(transport::BoxedMessage),
    Alert(String),
    Error{reconnect_allowed: bool, message: String},
    QueueSendComplete,
}

#[derive(Clone, Debug)]
pub enum Closed{
    Shutdown,
    LoginFailed,
    Rejected(String),
}

pub struct Client {
    send_queue: tokio::sync::mpsc::UnboundedSender<SendItem>,
    event_queue: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Event>>,
    jh: tokio::task::JoinHandle<Closed>,
}
impl Client {
    pub fn new(server: ThreemaServer, creds: Credentials) -> Self{
        // start connection service
        let (send_queue_s,send_queue_r) = tokio::sync::mpsc::unbounded_channel();
        let (event_queue_s,event_queue_r) = tokio::sync::mpsc::unbounded_channel();

        let jh = tokio::task::spawn(Self::keep_alive(server, creds, event_queue_s, send_queue_r));
        Client{
            send_queue: send_queue_s,
            event_queue: tokio::sync::Mutex::new(event_queue_r),
            jh,
        }
    }
    /// Wait for next event
    pub async fn event(&self) -> Option<Event> {
        self.event_queue.lock().await.recv().await
    }
    /// Upload message to the Server. When the function awaits the first time, the message is
    /// queued locally and will eventually be sent by the connection task.
    pub async fn send_message(&self, msg: transport::BoxedMessage) -> Result<(),Closed>{
        // create oneshot
        let (signal_s, signal_r) = tokio::sync::oneshot::channel();
        // put message in send_queue
        // TODO: "Shutdown" is the wrong message here!
        log::trace!("Putting mesage to sent queue");
        self.send_queue.send(SendItem::Message(msg, signal_s)).map_err(|_| Closed::Shutdown)?;
        signal_r.await.map_err(|_| Closed::Shutdown)?;
        Ok(())
    }
    pub async fn send_ack(&self, ack: &Ack) -> Result<(), Closed>{
        self.send_queue.send(SendItem::Ack(*ack)).map_err(|_| Closed::Shutdown)?;
        Ok(())
        //self..envelope.sender_ack()
    }

    /// Currntly, this simply aborts the background tasks
    /// TODO: queued messages should be handled somehow!
    pub fn shutdown(&self) {
        self.jh.abort();
    }

    async fn keep_alive(server: ThreemaServer, creds: Credentials,
                        event_queue: tokio::sync::mpsc::UnboundedSender<Event>,
                        mut send_queue: tokio::sync::mpsc::UnboundedReceiver<SendItem>,
                    ) -> Closed {
        const BACKOFF_MAX: Duration = Duration::from_secs(180);
        const BACKOFF_MIN: Duration = Duration::from_millis(50);
        const KEEP_ALIVE: Duration = Duration::from_secs(180);
        // ack_queue: Default::default()
        let poison_pill = Arc::new(tokio::sync::Notify::new());
        'reconnect: loop {
            let mut write_half;
            //let mut ack_queue;
            let mut recv_task;
            
            let mut backoff = BACKOFF_MIN;
            let last_rcvd_echo_seq = Arc::new(AtomicU32::new(0));
            let mut next_echo;
            let mut last_sent_echo_seq = 0;
            let ack_queue = AckQueue::default();
            loop {
                let res = transport::connect(&server, &creds).await;
                match res {
                    Ok((r,w)) => {
                        write_half = w;
                        recv_task = AbortOnDrop{task:
                            tokio::task::spawn(Self::receive_loop(r, event_queue.clone(), last_rcvd_echo_seq.clone(), ack_queue.clone()))};
                        break;
                    }
                    Err(e) => {
                        log::warn!("Connection failed: {}, reconnecting in {}ms", e, backoff.as_millis());
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(BACKOFF_MAX, 2*backoff);
                    }
                }
            };

            // TODO: nachrichten weniger kopieren
            let previously_sent = ack_queue.lock().unwrap().values().map(|(m,_ping)| m.clone()).collect::<Vec<_>>();
            for msg in previously_sent {
                let sent = write_half.send_message(&msg, transport::ClientToServer).await;
                if sent.is_err() {
                    continue 'reconnect;
                }
            }
            let sent = event_queue.send(Event::Connected);
            if sent.is_err() {
                return Closed::Shutdown;
            }
            next_echo = tokio::time::Instant::now() + KEEP_ALIVE;
            loop {
                tokio::select!{
                    _a = &mut recv_task.task => {
                        log::trace!("receiver ended");
                        // receive died -> reconnect
                        break; // this goes to the connect loop
                    }
                    () = tokio::time::sleep_until(next_echo) => {
                        log::trace!("echo timer");
                        // check echo
                        if last_rcvd_echo_seq.load(std::sync::atomic::Ordering::SeqCst) != last_sent_echo_seq {
                            break;
                        }
                        // request new echo
                        last_sent_echo_seq = last_sent_echo_seq.wrapping_add(1);
                        let sent = write_half.echo_request(last_sent_echo_seq).await;
                        if sent.is_err() {
                            break;
                        }
                        next_echo = tokio::time::Instant::now() + KEEP_ALIVE;
                    }
                    msgo = send_queue.recv() => {
                        log::trace!("got from send queue: {:?}", msgo);
                        match msgo {
                            Some(SendItem::Message(msg, pingback)) => {

                                let expected_ack = msg.envelope.recipient_ack();
                                let sent = write_half.send_message(&msg, transport::ClientToServer).await;
                                ack_queue.lock().unwrap().insert(expected_ack,(msg,pingback));
                                if let Err(e) = sent {
                                    log::trace!("error while sending: {}", &e);
                                    break;
                                }
                            }
                            Some(SendItem::Ack(ref ack)) => {
                                let sent = write_half.send_ack(ack, transport::Direction::ClientToServer).await;
                                if let Err(e) = sent {
                                    log::trace!("error while sending: {}", &e);
                                    break;
                                }
                            }
                            None => {
                                poison_pill.notify_waiters();
                                poison_pill.notify_one();
                                return Closed::Shutdown;
                            }
                        }
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
            ack_queue: AckQueue,
            ) {
        loop {
            let res = r.receive_packet().await;
            match res {
                Ok(packet) => {
                    match packet {
                        transport::Packet::BoxedMessageDownload(m) => {
                            let _ = event_queue.send(Event::BoxedMessage(m));
                        }
                        transport::Packet::QueueSendComplete => {
                            let _ = event_queue.send(Event::QueueSendComplete);
                        }
                        transport::Packet::EchoReply(i) => {
                            last_received_echo.store(i, std::sync::atomic::Ordering::SeqCst);
                        }
                        transport::Packet::AckUpload(ack) =>{
                            if let Some((_, signal)) = ack_queue.lock().unwrap().remove(&ack) {
                                let _res = signal.send(());
                            }
                            else {
                                log::warn!("INCOMING_MESSAGE_ACK for unknown message: {:?}", ack);
                            }
                        }
                        unexpected => {
                            log::warn!("Received packet with unexpected payload type from server: {:?}", unexpected);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("receive_loop: {}", e);
                    return;
                }
            }
        }
    }
}
type AckQueue = Arc<std::sync::Mutex<std::collections::HashMap<Ack, (BoxedMessage, oneshot::Sender<()>)>>>;
#[derive(Debug)]
enum SendItem {
    Message(transport::BoxedMessage, tokio::sync::oneshot::Sender<()>),
    Ack(Ack)
}
struct AbortOnDrop<T>{task: tokio::task::JoinHandle<T>}
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        log::trace!("AbortOnDrop::drop");
        self.task.abort();
    }
}
