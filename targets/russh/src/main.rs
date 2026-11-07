use std::{sync::Arc, time::Duration};
use russh::{server::{self, Auth, Msg, Server as _, Session}, Channel, ChannelId};

#[derive(Clone)]
struct Server;

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
        Ok(if user == "test" && password == "test" { Auth::Accept } else { Auth::reject() })
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
    let config = server::Config {
        methods: (&[russh::MethodKind::Password][..]).into(),
        auth_rejection_time: Duration::from_millis(100),
        auth_rejection_time_initial: Some(Duration::from_millis(100)),
        keys: vec![russh::keys::PrivateKey::random(
            &mut rand::rng(), russh::keys::Algorithm::Ed25519,
        )?],
        ..Default::default()
    };
    let socket = tokio::net::TcpListener::bind(("0.0.0.0", 22)).await?;
    Server.run_on_socket(Arc::new(config), &socket).await?;
    Ok(())
}
