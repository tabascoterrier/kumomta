# implicit_tls

When true, the listener expects clients to initiate TLS immediately upon connection (implicit TLS / SMTPS), rather than upgrading via STARTTLS.

The default, if unspecified, is false.

```lua
kumo.start_esmtp_listener {
    -- ..
    implicit_tls = true,
  }
```
