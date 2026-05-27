# implicit_tls

When true, the listener expects clients to initiate TLS immediately upon connection (implicit TLS / SMTPS), rather than upgrading via STARTTLS.

A TLS certificate and private key should be configured via [tls_certificate](tls_certificate.md) and [tls_private_key](tls_private_key.md); if they are not, a self-signed certificate is generated, just as with `STARTTLS`.

On a listener with `implicit_tls = true`, `STARTTLS` is not advertised in the `EHLO` response, since TLS is already active.

The default, if unspecified, is false.

```lua
kumo.start_esmtp_listener {
  -- ..
  implicit_tls = true,
}
```
