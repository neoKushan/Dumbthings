package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.tls.crypto.TlsSecret;
import java.security.SecureRandom;
import java.lang.reflect.Field;

/**
 * BcTlsCrypto that captures the 48-byte TLS 1.2 master secret live during PRF derivation.
 * Must live in BC's own package because {@code adoptLocalSecret} is package-private; on Android
 * the dex has no jar-signer check so this loads fine. Validated against a loopback DTLS handshake
 * (client master == server master, non-zero).
 */
public class CapCrypto extends BcTlsCrypto {
    public final byte[][] cap = new byte[1][];

    public CapCrypto(SecureRandom r) { super(r); }

    static byte[] data(Object s) {
        for (Class<?> c = s.getClass(); c != null; c = c.getSuperclass())
            try { Field f = c.getDeclaredField("data"); f.setAccessible(true); return (byte[]) f.get(s); }
            catch (NoSuchFieldException ignore) {} catch (Exception e) { return null; }
        return null;
    }

    BcTlsSecret adoptLocalSecret(byte[] d) {
        final byte[][] c = cap;
        return new BcTlsSecret(this, d) {
            public synchronized TlsSecret deriveUsingPRF(int prf, String label, byte[] seed, int len) {
                TlsSecret r = super.deriveUsingPRF(prf, label, seed, len);
                if (len == 48 && label != null && label.contains("master secret") && c[0] == null) {
                    byte[] mm = data(r);
                    if (mm != null) c[0] = mm.clone();
                }
                return r;
            }
        };
    }
}
