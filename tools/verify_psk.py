import sys
from smartthings_local.protocol.owner_psk import (
    derive_mfg_certificate_owner_psk,
    CONFIRMED_MFG_CERTIFICATE_OXM_LABEL,
    STANDARD_MFG_CERTIFICATE_OXM_LABEL,
)

d = {}
for line in open(sys.argv[1] if len(sys.argv) > 1 else "diag.txt"):
    line = line.strip()
    if "=" in line:
        k, v = line.split("=", 1)
        d[k] = v

MS = bytes.fromhex(d["MS"]); CR = bytes.fromhex(d["CR"]); SR = bytes.fromhex(d["SR"])
OU = bytes.fromhex(d["OU"]); DU = bytes.fromhex(d["DU"]); CIPHER = d["CIPHER"]
reported = d.get("PSK", "")

print(f"master_secret len={len(MS)} all_zero={not any(MS)} first8={MS[:8].hex()}")
print(f"client_random len={len(CR)}  server_random len={len(SR)}")
print(f"owner_uuid={OU.hex()}  device_uuid={DU.hex()}  cipher={CIPHER}")
print(f"standalone PSK = {reported}")
for name, lbl in (("conmfgcert", CONFIRMED_MFG_CERTIFICATE_OXM_LABEL),
                  ("mfgcert", STANDARD_MFG_CERTIFICATE_OXM_LABEL)):
    psk = derive_mfg_certificate_owner_psk(
        master_secret=MS, client_random=CR, server_random=SR,
        owner_uuid=OU, device_uuid=DU, cipher_name=CIPHER, oxm_label=lbl,
    ).hex()
    match = " <== MATCHES standalone" if psk == reported else ""
    print(f"  reference[{name}] = {psk}{match}")
