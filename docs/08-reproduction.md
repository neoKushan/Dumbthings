# 08 — Reproduction and test rig

What it took to run this end-to-end, and how to verify the result. This is a research
procedure on your own hardware, not a turnkey product.

## Rig

| Piece | Role |
|---|---|
| Android phone/tablet | runs the standalone OTM app ([`android/`](../android/)). **Not rooted** for the app itself. |
| The device | a factory-reset Samsung OCF appliance in BLE range |
| A Samsung account | signed into SmartThings; supplies the account **bearer** and the `locationId`/`roomId` |
| A host + mitmproxy *(for the bearer only)* | to read the SmartThings account bearer from the app's TLS (okhttp honours system proxy + CA) |
| Home Assistant + `smartthings-local` | to consume/verify the resulting `OwnerPSK` |

> The rig used during research also had a rooted tablet with Frida for the *reverse
> engineering* (capturing the plaintext OTM to decode the sequence). That was for discovery;
> the onboarding app itself needs no root.

## Flow

1. **Collect the cloud inputs once.** From the signed-in SmartThings app, obtain the account
   **bearer** (e.g. via mitmproxy — okhttp honours the system CA, so there is no pinning) and
   the account's `locationId` + `roomId`. These are account-stable.
2. **Factory-reset the device** so it is unowned and advertising over BLE. (A device that was
   heavily cycled may need a power-cycle to un-wedge its BLE — see [`06`](06-ble-ocf-transport.md).)
3. **Run the app:** scan → pick the device → enter Wi-Fi → start. It performs the OTM
   ([`03`](03-otm-sequence.md)), derives the key ([`04`](04-ownerpsk-derivation.md)), and
   prompts for the physical confirm.
4. **Press the device's confirm** (Volume-Down on the soundbar) when prompted. The app then
   reconnects over owner-PSK, mints the device JWT, and runs EasySetup
   ([`05`](05-easysetup-and-cloud.md)).
5. The device joins Wi-Fi and registers → `ES_COMPLETE`. The app outputs the **owner UUID** and
   **`OwnerPSK` (hex)**.

## Verify

- **Ownership stuck:** read `/oic/sec/doxm` → `owned:true`, `devowneruuid` = your owner UUID.
- **Registered:** the device appears in the SmartThings account.
- **Key works locally** (the real test), using the same library HA uses:

```python
import uuid
from smartthings_local.protocol.ocf_multicast import discover_ocf_responders, secure_ports_for_di
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.auth import PskAuth

DI = "<DEVICE_DI>"
disc = discover_ocf_responders("<device-ip>", interface_address="<host-ip>")
port = secure_ports_for_di(disc.responders, DI)[0]

sess = DtlsCoapSession("<device-ip>", port,
        auth=PskAuth(identity=uuid.UUID("<OWNER_UUID>").bytes,
                     key=bytes.fromhex("<OWNERPSK_HEX>")))
sess.connect(); sess.start_reader()
code, body = sess.get(["oic", "d"])     # expect 2.05; body carries the device di + name
sess.close()
```

A `2.05` response whose `/oic/d` `di` matches the device confirms the key. Import the owner
UUID as the identity and the hex key via LocalThings' **Owner PSK** option.

## When a reconnect fails

- `bad_record_mac` on the owner-PSK handshake, with an otherwise-correct derivation → **try the
  other OXM label** (`oic.sec.doxm.mfgcert` ↔ `x.org.iotivity.conmfgcert`). The reference app
  tries both.
- A derived key that is all-plausible-but-wrong across *every* label → suspect a **zeroed
  master secret** ([`04`](04-ownerpsk-derivation.md), trap 1).
- Ownership that reverts to `owned:false` → EasySetup didn't reach `ES_COMPLETE`; check the
  device JWT (fresh? correct `locationId`/`roomId`?) and that the owner-PSK session actually
  carried the writes.
