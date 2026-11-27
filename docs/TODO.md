# TODO

- **Code signing.** Releases are ad-hoc signed on macOS and unsigned on Windows unless the
  signing secrets in [RELEASING.md](RELEASING.md#4-signing-and-notarization) are set, so
  Gatekeeper and SmartScreen warn users. Decide whether to get an Apple Developer ID and a
  Windows Authenticode certificate.
- **Advanced routing & HTTP/SOCKS split UX.** The Advanced routing drawer (multi-condition
  rules, failover chains, bypass/inbound) and HTTP/SOCKS split override tables in Proxy
  Routing are kept as-is for now. Rework their UX or remove them in a future pass.
