use crate::kumod::{DaemonWithMaildirOptions, MailGenParams};
use bstr::ByteSlice;
use k9::assert_equal;
use kumo_api_types::TraceSmtpV1Payload::Callback;
use kumo_log_types::RecordType::{Delivery, Reception};
use rfc5321::tokio_rustls::rustls::pki_types::ServerName;
use rfc5321::{SmtpClient, SmtpClientTimeouts, TlsOptions};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Connect to an `implicit_tls = true` listener: optionally write a cleartext PROXY protocol
/// header first (as a real proxy would, ahead of the forwarded TLS stream), then perform the
/// TLS handshake and return a client ready to speak SMTP over the encrypted channel.
async fn connect_implicit_tls(
    addr: SocketAddr,
    proxy_header: Option<&[u8]>,
) -> anyhow::Result<SmtpClient> {
    let mut tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    if let Some(header) = proxy_header {
        tcp.write_all(header).await?;
        tcp.flush().await?;
    }

    let connector = TlsOptions {
        insecure: true,
        ..Default::default()
    }
    .build_tls_connector()
    .await?;

    let server_name = ServerName::try_from("localhost")?.to_owned();
    let tls_stream = connector.connect(server_name, tcp).await?;

    Ok(SmtpClient::with_stream(
        tls_stream,
        addr.to_string(),
        SmtpClientTimeouts::short_timeouts(),
    ))
}

/// Validate that an `implicit_tls = true` listener accepts a TLS-wrapped
/// connection (no STARTTLS), records TLS parameters on the Reception log,
/// produces an ESMTPS `Received:` header, and does not advertise STARTTLS.
#[tokio::test]
async fn tls_implicit() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_SOURCE_IMPLICIT_TLS", "true")
        .start()
        .await?;

    let tracer = daemon.trace_server().await?;

    // Connect to the source listener and wrap the socket in TLS before
    // sending any SMTP commands.
    let addr = daemon.source.listener("smtp");
    let mut client = connect_implicit_tls(addr, None).await?;

    let connect_timeout = client.timeouts().connect_timeout;
    let banner = client.read_response(None, connect_timeout).await?;
    anyhow::ensure!(banner.code == 220, "unexpected banner: {banner:#?}");
    let capabilities = client.ehlo("localhost").await?;

    // STARTTLS must not be advertised once TLS is already active.
    anyhow::ensure!(
        !capabilities.contains_key("STARTTLS"),
        "STARTTLS should not be advertised on an implicit_tls listener"
    );

    let response = MailGenParams::default().send(&mut client).await?;
    anyhow::ensure!(response.code == 250);

    daemon
        .wait_for_source_summary(
            |summary| summary.get(&Delivery).copied().unwrap_or(0) > 0,
            Duration::from_secs(50),
        )
        .await;

    // The listener parameters (including smtp_server_get_dynamic_parameters)
    // are resolved before the TLS handshake on an implicit_tls listener; the
    // event must fire exactly once for the session, not again in the SMTP
    // phase.
    tracer
        .wait_for(
            |events| {
                events.iter().any(|event| {
                    matches!(&event.payload, Callback{name,..}
                        if name == "smtp_server_get_dynamic_parameters")
                })
            },
            Duration::from_secs(10),
        )
        .await;
    let trace_events = tracer.stop().await?;
    let dynamic_params_calls = trace_events
        .iter()
        .filter(|event| {
            matches!(&event.payload, Callback{name,..}
                if name == "smtp_server_get_dynamic_parameters")
        })
        .count();
    assert_equal!(dynamic_params_calls, 1);

    daemon.stop_both().await?;

    let source_logs = daemon.source.collect_logs().await?;
    let reception = source_logs
        .iter()
        .find(|record| record.kind == Reception)
        .unwrap();
    eprintln!("source reception: {reception:#?}");
    assert!(reception.tls_cipher.is_some());
    assert!(reception.tls_protocol_version.is_some());

    let mut messages = daemon.extract_maildir_messages()?;
    assert_equal!(messages.len(), 1);
    let parsed = messages[0].parsed()?;
    let trace = parsed
        .headers()
        .get_first("Received")
        .unwrap()
        .as_unstructured()
        .unwrap();
    println!("trace: {trace}");
    assert!(trace.contains_str(&format!(
        "with ESMTPS ({}:{})",
        reception.tls_protocol_version.as_ref().unwrap(),
        reception.tls_cipher.as_ref().unwrap()
    )));

    Ok(())
}

/// Validate that a listener configured with *both* `implicit_tls = true` and
/// `require_proxy_protocol = true` works: the cleartext PROXY header is consumed from the raw
/// socket before the TLS handshake (rather than being fed into the TLS acceptor, which would
/// abort the handshake), the advertised client address is adopted, and the message is received
/// over TLS and relayed.
#[tokio::test]
async fn tls_implicit_proxy_protocol() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_SOURCE_IMPLICIT_TLS", "true")
        .env("KUMOD_SOURCE_REQUIRE_PROXY_PROTOCOL", "1")
        .start()
        .await?;

    let addr = daemon.source.listener("smtp");

    // A real proxy sends the PROXY header in cleartext, then forwards the client's TLS stream.
    // Advertise a distinctive (documentation-range) source address so we can confirm it is
    // adopted as the peer address.
    let proxy_header = b"PROXY TCP4 192.0.2.1 198.51.100.1 25 465\r\n";
    let mut client = connect_implicit_tls(addr, Some(proxy_header)).await?;

    let connect_timeout = client.timeouts().connect_timeout;
    let banner = client.read_response(None, connect_timeout).await?;
    anyhow::ensure!(banner.code == 220, "unexpected banner: {banner:#?}");
    let capabilities = client.ehlo("localhost").await?;
    anyhow::ensure!(
        !capabilities.contains_key("STARTTLS"),
        "STARTTLS should not be advertised on an implicit_tls listener"
    );

    let response = MailGenParams::default().send(&mut client).await?;
    anyhow::ensure!(response.code == 250);

    daemon
        .wait_for_source_summary(
            |summary| summary.get(&Delivery).copied().unwrap_or(0) > 0,
            Duration::from_secs(50),
        )
        .await;

    daemon.stop_both().await?;

    let source_logs = daemon.source.collect_logs().await?;
    let reception = source_logs
        .iter()
        .find(|record| record.kind == Reception)
        .unwrap();
    eprintln!("source reception: {reception:#?}");

    // The handshake completed only because the PROXY header was consumed first.
    assert!(reception.tls_cipher.is_some());

    // The peer address logged for the reception must be the one advertised in the PROXY header,
    // proving the header was parsed and adopted ahead of the TLS handshake.
    let peer_address = reception.peer_address.as_ref().unwrap();
    assert_equal!(peer_address.addr.to_string(), "192.0.2.1");

    Ok(())
}

/// Validate that a rejection raised by `smtp_server_get_dynamic_parameters` on an
/// `implicit_tls = true` listener is delivered to the client. The event runs before
/// the TLS handshake, when there is no channel to report a rejection on, so it is
/// deferred and must arrive in place of the banner once the handshake completes.
#[tokio::test]
async fn tls_implicit_dynamic_params_reject() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_SOURCE_IMPLICIT_TLS", "true")
        .env("KUMOD_SOURCE_DYNAMIC_PARAMS_REJECT", "1")
        .start()
        .await?;

    let addr = daemon.source.listener("smtp");
    let mut client = connect_implicit_tls(addr, None).await?;

    let connect_timeout = client.timeouts().connect_timeout;
    let banner = client.read_response(None, connect_timeout).await?;
    anyhow::ensure!(
        banner.code == 421,
        "expected the deferred rejection in place of the banner: {banner:#?}"
    );
    anyhow::ensure!(
        banner
            .content
            .contains("rejected by smtp_server_get_dynamic_parameters"),
        "unexpected rejection message: {banner:#?}"
    );

    daemon.stop_both().await?;

    Ok(())
}
