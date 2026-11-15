# Tools

Small helpers used to reverse-engineer and verify the flow. Python ones assume the
[`smartthings-local`](https://pypi.org/project/smartthings-local/) package and `cbor2`;
Frida ones assume a rooted capture device (reverse engineering only — the onboarding app
needs no root).

| Tool | What it does |
|---|---|
| `decode_capture.py` | Decodes a hex capture log → CoAP-over-TCP (RFC 7252/8323) → CBOR. Turns raw frames into the readable `/oic/sec/*` exchanges in [docs/03](../docs/03-otm-sequence.md). `python decode_capture.py capture.log` |
| `otm_bodies.js` + `bodies_capture.py` | Frida hooks on the OCF CBOR serializer (`liboctbstack`) in the SmartThings app, to capture the **plaintext** OTM request/response bodies as they're built — before DTLS. This is how the exact sequence was recovered. |
| `otm_psk.js` | Frida hook on `CAGenerateOwnerPSK` to observe the derived `OwnerPSK` (for comparing against an independent derivation). |
| `verify_psk.py` | Re-derives the `OwnerPSK` from a `diag.txt` dump using the reference `derive_mfg_certificate_owner_psk`, with **both** OXM labels, and compares to the app's output. Proves the Java port and tells you which label the device used. |
| `mitm_addon.py` | mitmproxy addon that logs Samsung account / OAuth traffic in cleartext — how the SmartThings **account bearer** was obtained (okhttp honours the system proxy + CA, so no pinning). |
| `mock_cloud.py` | A minimal **local OCF cloud** that answers sign-up/sign-in — kept as a reference for anyone who wants to build their own. **Unproven POC:** only taken as far as getting a device to *connect* to it; reaching and holding `ES_COMPLETE` through the mock was never verified. Not a supported path — the app uses the real cloud. Set `MOCKCLOUD_DIR` and `MOCKCLOUD_HOST`. |

## The bearer, briefly

`mitm_addon.py` exists because the SmartThings account bearer (needed to mint the device JWT —
[docs/05](../docs/05-easysetup-and-cloud.md)) comes from a first-party OAuth you can't drive
yourself. With the mitmproxy CA installed on the capture device and the SmartThings app routed
through it, the bearer appears on the first authenticated request (e.g.
`GET auth-global.api.smartthings.com/users/me`).

## Mock cloud vs real cloud

The app uses the **real cloud**: the device registers to your SmartThings account (and then
appears in the app) via the device JWT (bearer → `nexo/auth/jwt`). This is the proven, supported
path — see [docs/05](../docs/05-easysetup-and-cloud.md).

`mock_cloud.py` is a **research POC only**, included so others can build on the idea. It was taken
no further than getting a device to *connect* to a local server standing in for the cloud;
reaching and holding `ES_COMPLETE` through it was **not** verified. Don't treat it as a working
local-only alternative.
