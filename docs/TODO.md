# TODO

## Upstream engine (`rusty-conduit-ssh`): MITM CA loading

Found while testing MITM CA upload with CA files made by `openssl` (LibreSSL 3.3.6 on macOS). Both
are in the engine's loader (`src/mitm/ca.rs`), so they affected the old path-based CAs as well.

- [ ] **EC keys with explicit curve parameters are rejected, with a misleading error.** LibreSSL's
  `openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1` writes the curve as explicit
  parameters unless `-pkeyopt ec_param_enc:named_curve` is added. `ring` only accepts named curves,
  so `KeyPair::try_from` fails. In a PKCS#12 bundle `from_pkcs12` skips the key and reports
  "the MITM CA private key does not match the CA certificate"; as PEM it reports "Could not parse
  key pair". Either accept such keys (rewrite them to the named-curve OID when the parameters match
  P-256 or P-384) or report that explicit curve parameters are unsupported and how to re-encode them.
- [ ] **Encrypted PKCS#8 using PBES2 with the HMAC-SHA1 PRF is unsupported.** The error is
  "PKCS#5 algorithm 1.2.840.113549.2.7 is unsupported". The engine's own hint suggests
  `openssl pkcs8 -topk8 -v2 aes-256-cbc`, which on LibreSSL (macOS) produces exactly that PRF;
  OpenSSL 3 defaults to HMAC-SHA256 and works. Either support the SHA-1 PRF or change the hint
  (for example to a PKCS#12 bundle, or `-v1 PBE-SHA1-3DES`, which does work).
