# 04 — Deriving the `OwnerPSK` (and three traps)

The `OwnerPSK` is IoTivity's manufacturer-certificate derivation: a two-stage TLS 1.2
`P_hash(SHA-256)` over the DTLS session state. Both the device and the mediator compute it.

## The derivation

```
key_block = P_hash_SHA256( master_secret, "key expansion",
                           server_random + client_random, key_block_len )

OwnerPSK  = P_hash_SHA256( key_block, OXM_LABEL,
                           owner_uuid + device_uuid, 16 )
```

- `master_secret` (48 bytes), `client_random`, `server_random` (32 bytes each) come from the
  **manufacturer-certificate DTLS session**.
- `owner_uuid` first, `device_uuid` second — **raw 16-byte big-endian** UUIDs.
- `key_block_len` depends on the negotiated cipher. For
  `ECDHE-ECDSA-AES128-GCM-SHA256` (the one this soundbar negotiates) it is **120**.
  (Other lengths exist, e.g. 40 for the CCM suites, 96 for `AES128-SHA256`.)
- `OXM_LABEL` — **see trap 2**.

This matches `smartthings_local.protocol.owner_psk.derive_mfg_certificate_owner_psk`; the
reference app is a line-for-line Java port, verified byte-identical against the Python on the
same inputs.

## Trap 1 — the master secret is captured from zeros

TLS stacks treat the master secret as sensitive and **destroy it after the handshake**. With
BouncyCastle, `SecurityParameters.getMasterSecret()` in `notifyHandshakeComplete` returns a
`TlsSecret` whose bytes have already been **zeroed** — you get 48 `0x00`s, and the derivation
produces a wrong-but-valid-looking 16-byte key. Every key is different (the randoms and UUIDs
still vary), so nothing looks obviously broken until the PSK handshake fails with
`bad_record_mac`.

**Fix:** capture the master secret *live*, while it's being derived. BouncyCastle builds it via
`preMaster.deriveUsingPRF(prf, "master secret"|"extended master secret", seed, 48)`. Intercept
that:

```java
// CapCrypto extends BcTlsCrypto IN BouncyCastle's own package, because
// adoptLocalSecret is package-private. (On Android the dex has no jar-signer check.)
BcTlsSecret adoptLocalSecret(byte[] d) {
    return new BcTlsSecret(this, d) {
        public TlsSecret deriveUsingPRF(int prf, String label, byte[] seed, int len) {
            TlsSecret r = super.deriveUsingPRF(prf, label, seed, len);
            if (len == 48 && label != null && label.contains("master secret"))
                capture(r);           // the 48-byte master secret, intact
            return r;
        }
    };
}
```

Validated with a loopback DTLS handshake: with `CapCrypto` on both ends the captured master
secrets are **non-zero and identical** (client == server), i.e. the true shared secret.

> Note for the Python library: its `derive_mfg_certificate_owner_psk` is correct, but the
> released `dtls_session`/`dtls_handshake` expose no `master_secret`/`client_random`/
> `server_random`, so it has no wired input source. Same gap, same fix idea: surface the
> handshake secrets.

## Trap 2 — the OXM label

The label fed into the second `P_hash` must match what the device used. Two are in circulation:

- `oic.sec.doxm.mfgcert` — the standard manufacturer-certificate label.
- `x.org.iotivity.conmfgcert` — the "confirmed" variant.

The physical confirm (Volume-Down) *looks* like it implies `conmfgcert`, and some references
use it — but **this HW-Q950A derives with `oic.sec.doxm.mfgcert`**. The two produce completely
different keys; only one authenticates. If a reconnect fails `bad_record_mac` with an otherwise
correct derivation, **try the other label.** The reference app simply tries both and keeps the
one whose ECDHE-PSK handshake succeeds.

## Trap 3 — identity and byte order

- The DTLS-PSK **identity is the owner UUID**, as **raw 16 bytes** (not the hyphenated string).
  The device matches it against the `subjectuuid` of the `cred` it stored.
- OCF UUIDs are **big-endian** (standard RFC 4122 byte order), not little-endian.
- ~6% of random UUIDs contain a `0x00` byte. Some PSK stacks (OpenSSL's DTLS 1.2 PSK client
  callback) pass the identity as a C string and truncate at the NUL. Use a stack that carries
  the identity with an explicit length (BouncyCastle does; so does `smartthings-local ≥0.1.23`).

## Putting the traps together

All three were present at once, and each produced a plausible wrong key, so they masked one
another: a zero master secret *and* an unverifiable label *and* (early on) a stack that could
mishandle the identity. The order that actually worked: fix the master-secret capture →
confirm the derivation byte-matches the reference on real inputs → let the reconnect try both
labels → `oic.sec.doxm.mfgcert` authenticates.
