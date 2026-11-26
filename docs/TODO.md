# TODO

No open items.

The two MITM CA loading issues found with LibreSSL-made CA files (EC keys with explicit curve
parameters, and PBES2 PKCS#8 with the HMAC-SHA1 PRF) are resolved in `rusty-conduit-engine`
`v0.2.0` (`src/mitm/ca.rs`).
