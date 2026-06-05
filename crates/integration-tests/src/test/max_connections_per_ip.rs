use crate::kumod::DaemonWithMaildirOptions;
use rfc5321::{SmtpClient, SmtpClientTimeouts};
use std::time::Duration;

/// Verify that `max_connections_per_ip` caps the number of concurrent
/// connections from a single source IP, and that closing a connection frees a
/// slot for a new one.
#[tokio::test]
async fn max_connections_per_ip() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_MAX_CONNECTIONS_PER_IP", "2")
        .start()
        .await?;

    // Two concurrent connections from this IP are allowed; hold them open.
    // `smtp_client` reads the 220 banner and issues EHLO, so by the time it
    // returns the per-IP lease has been acquired.
    let _client1 = daemon.smtp_client().await?;
    let client2 = daemon.smtp_client().await?;

    // A third concurrent connection is rejected: the limit is enforced before
    // the banner, so we receive a 421 in place of the 220 greeting.
    let addr = daemon.source.listener("smtp");
    let mut client3 = SmtpClient::new(addr, SmtpClientTimeouts::short_timeouts()).await?;
    let banner = client3.read_response(None, Duration::from_secs(5)).await?;
    eprintln!("third connection banner: {banner:?}");
    anyhow::ensure!(
        banner.code == 421,
        "third concurrent connection should be denied with 421, got {banner:?}"
    );
    drop(client3);

    // Closing one of the held connections must free a slot. The lease release
    // happens asynchronously once the server observes the disconnect, so retry
    // briefly until a fresh connection is accepted.
    drop(client2);

    let mut accepted = false;
    for _ in 0..50 {
        if daemon.smtp_client().await.is_ok() {
            accepted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        accepted,
        "a new connection should be accepted after a held connection is closed"
    );

    daemon.stop_both().await?;
    Ok(())
}
