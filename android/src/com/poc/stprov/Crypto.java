package com.poc.stprov;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.util.UUID;

/** IoTivity manufacturer-certificate OwnerPSK derivation (TLS1.2 P_hash SHA-256),
 *  ported verbatim from smartthings_local/protocol/owner_psk.py. */
public class Crypto {
    // Default OXM label; this HW-Q950A derives with the standard label. Otm's reconnect
    // tries both this and "x.org.iotivity.conmfgcert", so it's only the first guess.
    public static final byte[] OXM_LABEL = "oic.sec.doxm.mfgcert".getBytes();

    static int keyBlockLen(String cipher) {
        switch (cipher) {
            case "ECDHE-ECDSA-AES128-SHA256": return 96;
            case "ECDHE-ECDSA-AES128-CCM": case "ECDHE-ECDSA-AES128-CCM8": return 40;
            case "ECDHE-ECDSA-AES128-GCM-SHA256": case "AES128-GCM-SHA256": return 120;
            case "AES256-SHA256": return 128;
            case "ECDHE-ECDSA-AES256-SHA384": return 160;
            case "ECDHE-ECDSA-AES256-GCM-SHA384": return 184;
            default: throw new IllegalArgumentException("unexpected mfg-cert cipher: " + cipher);
        }
    }

    static byte[] hmacSha256(byte[] key, byte[] data) {
        try { Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key, "HmacSHA256")); return m.doFinal(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    /** TLS1.2 P_hash(SHA-256): PRF(key, label || r1 || r2, length). */
    static byte[] pHash(byte[] key, byte[] label, byte[] r1, byte[] r2, int length) {
        byte[] seed = concat(label, r1, r2);
        byte[] a = hmacSha256(key, seed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (out.size() < length) { out.writeBytes(hmacSha256(key, concat(a, seed))); a = hmacSha256(key, a); }
        byte[] all = out.toByteArray(), r = new byte[length];
        System.arraycopy(all, 0, r, 0, length);
        return r;
    }

    /** OwnerPSK = PRF( PRF(masterSecret,"key expansion",serverRandom+clientRandom,kbLen), oxmLabel, ownerUuid+deviceUuid, 16 ). */
    public static byte[] ownerPsk(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom,
                                  byte[] ownerUuid, byte[] deviceUuid, String cipher) {
        byte[] keyBlock = pHash(masterSecret, "key expansion".getBytes(), serverRandom, clientRandom, keyBlockLen(cipher));
        return pHash(keyBlock, OXM_LABEL, ownerUuid, deviceUuid, 16);
    }

    /** Same, with an explicit OXM label (to test candidates). */
    public static byte[] ownerPsk(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom,
                                  byte[] ownerUuid, byte[] deviceUuid, String cipher, byte[] label) {
        byte[] keyBlock = pHash(masterSecret, "key expansion".getBytes(), serverRandom, clientRandom, keyBlockLen(cipher));
        return pHash(keyBlock, label, ownerUuid, deviceUuid, 16);
    }

    public static byte[] uuidBytes(UUID u) {
        byte[] b = new byte[16];
        long hi = u.getMostSignificantBits(), lo = u.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) { b[i] = (byte)(hi >>> (56 - 8*i)); b[8+i] = (byte)(lo >>> (56 - 8*i)); }
        return b;
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }
}
