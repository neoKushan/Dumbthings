# Traces

**No raw captures live here.** The original packet/Frida/mitmproxy logs are dense with real
account, device and network identifiers (hundreds of occurrences), so they are excluded by
design. Instead this folder holds **curated, placeholder-substituted excerpts** that show the
*shape* of a capture without leaking anything.

- [`otm-decoded-sample.log`](otm-decoded-sample.log) — a decoded manufacturer-cert OTM +
  owner-PSK EasySetup, as `decode_capture.py` would render it, with every identifier replaced.

To produce your own (on your own device/account): capture with the Frida hooks in
[`../tools`](../tools) and decode with `decode_capture.py`. Keep the raw output private.
