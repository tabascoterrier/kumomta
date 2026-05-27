use crate::kumod::{DaemonWithMaildirOptions, MailGenParams};
use bstr::ByteSlice;
use k9::assert_equal;
use kumo_log_types::RecordType::{Delivery, Reception};
use rfc5321::tokio_rustls::rustls::pki_types::ServerName;
use rfc5321::{SmtpClient, SmtpClientTimeouts, TlsOptions};
use std::time::Duration;
use tokio::net::TcpStream;

/// Validate that an `implicit_tls = true` listener accepts a TLS-wrapped
/// connection (no STARTTLS), records TLS parameters on the Reception log,
/// produces an ESMTPS `Received:` header, and does not advertise STARTTLS.
#[tokio::test]
async fn tls_implicit() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_SOURCE_IMPLICIT_TLS", "true")
        .start()
        .await?;

    // Connect to the source listener and wrap the socket in TLS before
    // sending any SMTP commands.
    let addr = daemon.source.listener("smtp");
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    let connector = TlsOptions {
        insecure: true,
        ..Default::default()
    }
    .build_tls_connector()
    .await?;

    let server_name = ServerName::try_from("localhost")?.to_owned();
    let tls_stream = connector.connect(server_name, tcp).await?;

    let mut client = SmtpClient::with_stream(
        tls_stream,
        addr.to_string(),
        SmtpClientTimeouts::short_timeouts(),
    );

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
