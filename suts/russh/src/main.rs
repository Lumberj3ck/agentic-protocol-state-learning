// russh server for stream B1. Adapted from vendor/agentic-protocol-state-learning/targets/russh (Apache-2.0).
use std::{sync::Arc, time::Duration};
use russh::{server::{self, Auth, Msg, Server as _, Session}, Channel, ChannelId};
use russh::keys::{PublicKey, PublicKeyBase64};

#[derive(Clone)]
struct Server;

fn authorized(key: &PublicKey) -> bool {
    let blob = key.public_key_base64();
    match std::fs::read_to_string("/etc/psm/authorized_keys") {
        Ok(s) => s.lines().any(|l| l.split_whitespace().nth(1) == Some(blob.as_str())),
        Err(_) => false,
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self { self.clone() }
    fn handle_session_error(&mut self, error: russh::Error) {
        eprintln!("Session error: {error:?}");
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == "tester" && password == "correct-horse-battery" { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user == "tester" && authorized(key) { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    let config = server::Config {
        methods: (&[russh::MethodKind::Password, russh::MethodKind::PublicKey][..]).into(),
        auth_rejection_time: Duration::from_millis(100),
        auth_rejection_time_initial: Some(Duration::from_millis(100)),
        keys: vec![
            russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Rsa { hash: None })?,
            russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?,
        ],
        ..Default::default()
    };
    let socket = tokio::net::TcpListener::bind(("0.0.0.0", 22)).await?;
    Server.run_on_socket(Arc::new(config), &socket).await?;
    Ok(())
}
