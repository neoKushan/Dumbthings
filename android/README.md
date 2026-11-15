# Reference OTM app

A minimal, **unrooted** Android app that performs the manufacturer-certificate OTM, derives
the `OwnerPSK`, and drives the device through EasySetup to `ES_COMPLETE`. It is intentionally
dependency-light (no Gradle, no frameworks) so the protocol is easy to follow.

## Source map

| File | Responsibility |
|---|---|
| `OcfBle.java` / `BleOcf.java` | OCF-over-BLE: GATT connect, `ble_ocf` framing, CoAP-over-TCP (see [docs/06](../docs/06-ble-ocf-transport.md)) |
| `Otm.java` | the whole ceremony: unsecured setup → DTLS → 2-phase `doxm` → cred/acl/pstat/finalize → owner-PSK reconnect → EasySetup → JWT mint |
| `Crypto.java` | `OwnerPSK` derivation (TLS 1.2 `P_hash`), UUID bytes, key-block lengths |
| `org/bouncycastle/.../CapCrypto.java` | captures the DTLS master secret live (BouncyCastle zeroes it otherwise — [docs/04](../docs/04-ownerpsk-derivation.md)). Lives in BC's package on purpose. |
| `Cbor.java` | tiny CBOR encoder for the OCF payloads |
| `MainActivity.java` | UI glue: SmartThings login, scan, pick, Wi-Fi dialog, run, VERIFY OWNED, result dialog with per-field copy, LAN IP discovery |

## Build

See `build.sh`. In short: `javac` + `d8` + `aapt2` + `apksigner`, with **BouncyCastle 1.78.1**
jars in `libs/` (download from Maven Central; not committed). BouncyCastle must be on the
classpath *and* the dex inputs.

## Runtime input: one sign-in

**SmartThings login** (`StLoginActivity`) — a WebView to `account.smartthings.com/login`. The web
dashboard is cookie-authenticated, so after you sign in the app reads the **`_JTKN` cookie** (the
account JWT) from its own WebView cookie jar, validates it against `users/me`, fetches your
`locationId`/`roomId`, and writes them with the bearer to `files/st_cloud.txt` (private) to mint the
device JWT ([docs/05](../docs/05-easysetup-and-cloud.md)).

That one sign-in is all the cloud material needed: the device JWT minted from the bearer already
carries the account `uid`, and the Samsung device sec-code turned out to be unnecessary — so there
is no separate Samsung login. Fully **no-root**: the app reads its *own* WebView cookies — no system
CA, no proxy, no adb push. `st_cloud.txt` is runtime-only, never committed.

## Run

**1. SmartThings login** (once) → **2. Scan** → pick the device → enter Wi-Fi → **Pair +
register**. At the prompt, **press the device's physical confirm** (Volume-Down on the soundbar).
A result dialog shows the IP, `OwnerPSK`, and IDs — each with its own copy button — and confirms
the device appeared in your SmartThings account. **VERIFY OWNED** re-reads `doxm`; **SAVED DEVICES**
re-opens any saved device's values with on-demand LAN **IP** discovery.

## Debug aid

`Otm.java` writes `files/diag.txt` with the handshake master secret / randoms / UUIDs / derived
key, so a derivation can be checked off-device against the reference Python. It writes to
private storage only; remove it if you don't want it.

## Not rooted

The app needs no root: BLE for the OTM, plus one in-app WebView sign-in for the cloud material
(it reads only its own WebView). Root/Frida were used *only* during the original reverse
engineering to capture the plaintext OTM — see [docs/08](../docs/08-reproduction.md).
