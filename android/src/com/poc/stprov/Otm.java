package com.poc.stprov;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.CapCrypto;

/** Manufacturer-certificate OTM over OCF-BLE: unsecured setup -> DTLS handshake -> OwnerPSK -> secured provisioning. */
public class Otm {
    public interface Log { void log(String s); void prompt(String s); }
    final OcfBle ocf; final Log lg;
    public byte[] ownerPsk; public UUID ownerUuid = UUID.randomUUID(); public String deviceUuid;
    // cloud provisioning inputs (bearer harvested from the SmartThings web login) + Wi-Fi
    public String wifiSsid, wifiPwd, deviceIp;
    public int wifiWat = 3, wifiWet = 4;   // OCFWifiEnrollerAuthType/EncType ordinals: WPA2_PSK=3, AES=4
    public boolean cloudProvisioned;
    public String cloudBearer, cloudLocationId, cloudRoomId, cloudJwt;
    // EU prod shard (captured); region-specific
    static final String CLOUD_APN = "coaps+tcp://connect.samsungiotcloud.com";
    static final String CLOUD_CIS = "coaps+tcp://ocfclientcon-shard-eu02-euwest1.samsungiotcloud.com:443";
    static final String CLOUD_CLIENTID = "166135d296";
    // captured during the DTLS handshake
    volatile byte[] hsMaster, hsCr, hsSr; volatile int hsCs;

    public Otm(OcfBle o, Log l){ ocf=o; lg=l; }
    void log(String s){ if(lg!=null) lg.log(s); }

    static final int[] CIPHERS = {
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    };
    static String cipherName(int cs){
        switch(cs){
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: return "ECDHE-ECDSA-AES128-CCM8";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM: return "ECDHE-ECDSA-AES128-CCM";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: return "ECDHE-ECDSA-AES128-GCM-SHA256";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: return "ECDHE-ECDSA-AES128-SHA256";
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: return "ECDHE-ECDSA-AES256-GCM-SHA384";
            default: throw new IllegalArgumentException("cs=0x"+Integer.toHexString(cs));
        }
    }
    static String[] nonq(String[] s){ List<String> l=new ArrayList<>(); for(String x:s) if(!x.startsWith("?")) l.add(x); return l.toArray(new String[0]); }

    String post(byte[] payload, String... segs) throws Exception {
        byte[] r = ocf.request(0x02, payload, segs);
        Object[] pr = BleOcf.parseCoapTcp(r);
        log("POST /"+String.join("/",nonq(segs))+" -> "+(pr!=null?pr[0]:"?"));
        return pr!=null?(String)pr[0]:null;
    }

    @SuppressWarnings("unchecked")
    public void run(String oxmLabelHint) throws Exception {
        // --- Samsung provisioninginfo session: arms the device for OTM + the physical confirm ---
        String sessionId = "";
        try {
            Object[] pp = BleOcf.parseCoapTcp(ocf.request(0x01, null, "sec","provisioninginfo"));
            Map<Object,Object> pim = (Map<Object,Object>) Cbor.dec((byte[])pp[1]);
            Object sid = pim.get("x.com.samsung.provisioning.sessionid");
            sessionId = (sid != null && !sid.toString().isEmpty()) ? sid.toString()
                : new java.text.SimpleDateFormat("yyyyMMddHHmmss").format(new java.util.Date()) + String.format("%04x", new Random().nextInt(0x10000));
            log("provisioninginfo keys=" + pim.keySet());
            log("provisioninginfo: owned=" + pim.get("x.com.samsung.provisioning.owned") + " sessionid=" + sessionId);
        } catch (Exception e) { log("provisioninginfo GET failed: "+e); }
        post(Cbor.enc(Cbor.map("x.com.samsung.provisioning.sessionid", sessionId)), "sec","provisioninginfo");

        byte[] dx = ocf.request(0x01, null, "oic","sec","doxm");
        Object[] p = BleOcf.parseCoapTcp(dx);
        Map<Object,Object> doxm = (Map<Object,Object>) Cbor.dec((byte[])p[1]);
        deviceUuid = (String) doxm.get("deviceuuid");
        log("doxm: deviceuuid="+deviceUuid+" owned="+doxm.get("owned")+" oxms="+doxm.get("oxms"));

        post(Cbor.enc(Cbor.map("oxmsel", 2, "owned", false, "devowneruuid", "00000000-0000-0000-0000-000000000000", "rowneruuid", "00000000-0000-0000-0000-000000000000")), "oic","sec","doxm");
        post(Cbor.enc(Cbor.map("isop", false, "cm", 2, "tm", 0, "om", 4)), "oic","sec","pstat");

        // --- DTLS mfg-cert handshake ---
        // BC zeroes the master secret before notifyHandshakeComplete; CapCrypto captures it live
        // during PRF derivation (adoptLocalSecret is package-private, so CapCrypto lives in BC's package).
        CapCrypto crypto = new CapCrypto(new SecureRandom());
        DefaultTlsClient client = new DefaultTlsClient(crypto) {
            TlsContext ctx;
            public int[] getCipherSuites(){ return CIPHERS; }
            public ProtocolVersion[] getProtocolVersions(){ return new ProtocolVersion[]{ ProtocolVersion.DTLSv12 }; }
            public void init(TlsClientContext c){ super.init(c); ctx=c; }
            public TlsAuthentication getAuthentication(){
                return new TlsAuthentication(){
                    public void notifyServerCertificate(TlsServerCertificate c){ log("server cert ok ("+(c!=null&&c.getCertificate()!=null?c.getCertificate().getLength():0)+")"); }
                    public TlsCredentials getClientCredentials(CertificateRequest r){ return null; }
                };
            }
            public void notifyHandshakeComplete() throws IOException {
                try {
                    SecurityParameters sp = ctx.getSecurityParametersConnection();
                    hsCs = sp.getCipherSuite(); hsCr = sp.getClientRandom(); hsSr = sp.getServerRandom();
                    hsMaster = (crypto.cap[0] != null ? crypto.cap[0] : grabMaster(ctx));
                    log("handshake complete cipher=0x"+Integer.toHexString(hsCs)+" master="+(hsMaster==null?"null":hsMaster.length+"B"));
                } catch (Exception e){ log("capture err "+e); }
            }
        };
        log("DTLS handshake (mfg-cert) ...");
        DTLSClientProtocol proto = new DTLSClientProtocol();
        DTLSTransport dtls = proto.connect(client, ocf.dtlsTransport());

        if (hsMaster == null) throw new Exception("master secret not captured");
        byte[] ou = Crypto.uuidBytes(ownerUuid), du = Crypto.uuidBytes(UUID.fromString(deviceUuid));
        ownerPsk = Crypto.ownerPsk(hsMaster, hsCr, hsSr, ou, du, cipherName(hsCs));
        log("OwnerPSK = " + BleOcf.hex(ownerPsk));
        try { java.io.FileWriter fw = new java.io.FileWriter("/data/data/com.poc.stprov/files/diag.txt");
            fw.write("MS="+BleOcf.hex(hsMaster)+"\nCR="+BleOcf.hex(hsCr)+"\nSR="+BleOcf.hex(hsSr)
                +"\nOU="+BleOcf.hex(ou)+"\nDU="+BleOcf.hex(du)+"\nCIPHER="+cipherName(hsCs)
                +"\nPSK="+BleOcf.hex(ownerPsk)+"\n"); fw.close(); } catch (Exception e) { log("diag err "+e); }
        DTLSTransport pdtls = null;

        try {
        // --- secured OTM: exact 2-phase sequence captured from the real SmartThings app ---
        secureGet(dtls, "oic","sec","doxm");
        final String NIL = "00000000-0000-0000-0000-000000000000";
        // 1) ARM: doxm {owned:false, devowneruuid} -> device defers the reply until Volume-Down, then derives the PSK
        if (lg != null) lg.prompt("Press the confirm button on the device now to approve ownership.\n\nOn a soundbar this is Volume-Down; other devices may use a different button or combo. Waiting up to 60s...");
        Map<Object,Object> arm = new java.util.LinkedHashMap<>();
        arm.put("oxmsel", 2); arm.put("owned", false);
        arm.put("devowneruuid", ownerUuid.toString()); arm.put("rowneruuid", NIL);
        boolean committed = securePostWait(dtls, Cbor.enc(arm), 60000, "oic","sec","doxm");
        if (lg != null) lg.prompt(null);   // dismiss the confirm modal (pressed or timed out)
        log("ownership ARM (owned:false+devowner) reply=" + committed);
        // 2) owner cred - EMPTY privatedata; device fills in the PSK it generated (we derived the same one)
        securePost(dtls, Cbor.enc(Cbor.map(
            "creds", Arrays.asList(Cbor.map("credid",10,"subjectuuid",ownerUuid.toString(),"credtype",1,
                "privatedata", Cbor.map("encoding","oic.sec.encoding.base64","data",""))),
            "rowneruuid", ownerUuid.toString())), "oic","sec","cred");
        // 3) owner ACL - wildcard resource/rt/if, full permission (31)
        securePost(dtls, Cbor.enc(Cbor.map(
            "aclist", Cbor.map("aces", Arrays.asList(Cbor.map(
                "subjectuuid", ownerUuid.toString(),
                "resources", Arrays.asList(Cbor.map("href","*","rt",Arrays.asList("*"),"if",Arrays.asList("*"))),
                "permission", 31))),
            "rowneruuid", ownerUuid.toString())), "oic","sec","acl");
        // 4) pstat BEFORE finalize (anon session can still write; owner-ACL not yet enforced)
        securePost(dtls, Cbor.enc(Cbor.map("isop", false, "cm", 0, "tm", 0, "om", 4)), "oic","sec","pstat");
        // 5) FINALIZE: doxm {owned:true, devowneruuid} — LAST secured write, then RFNOP should hold on close
        Map<Object,Object> fin = new java.util.LinkedHashMap<>();
        fin.put("oxmsel", 2); fin.put("owned", true);
        fin.put("devowneruuid", ownerUuid.toString()); fin.put("rowneruuid", NIL);
        securePost(dtls, Cbor.enc(fin), "oic","sec","doxm");
        log("security provisioning done (2-phase doxm, empty cred); owner="+ownerUuid);

        // --- owner-PSK reconnect: after FINALIZE the anon mfg-cert session is dead (owner-ACL enforced),
        //     so EasySetup must ride a fresh OwnerPSK DTLS session (ECDHE-PSK 0xC037), as the real app does ---
        boolean doCloud = cloudBearer != null && !cloudBearer.isEmpty()
            && wifiSsid != null && !wifiSsid.isEmpty();
        if (doCloud) {
            String jwt = (cloudJwt != null && !cloudJwt.isEmpty()) ? cloudJwt
                       : mintJwt(cloudBearer, cloudLocationId, cloudRoomId);
            if (jwt == null || jwt.isEmpty()) {
                log("JWT unavailable -> cloud skipped; OwnerPSK still valid for LocalThings");
            } else {
                try { dtls.close(); } catch (Exception e) {}
                log("anon session closed; owner-PSK reconnect (ECDHE-PSK 0xC037), trying OXM labels ...");
                String[][] cands = {{"mfgcert","oic.sec.doxm.mfgcert"},{"conmfgcert","x.org.iotivity.conmfgcert"}};
                for (String[] cand : cands) {
                    byte[] cpsk = Crypto.ownerPsk(hsMaster, hsCr, hsSr, ou, du, cipherName(hsCs), cand[1].getBytes());
                    log("  try label="+cand[0]+" psk="+BleOcf.hex(cpsk));
                    ocf.resetDtls();
                    try {
                        TlsPSKIdentity pskId = new BasicTlsPSKIdentity(Crypto.uuidBytes(ownerUuid), cpsk);
                        PSKTlsClient pskClient = new PSKTlsClient(crypto, pskId){
                            public int[] getCipherSuites(){ return new int[]{ CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 }; }
                            public ProtocolVersion[] getProtocolVersions(){ return new ProtocolVersion[]{ ProtocolVersion.DTLSv12 }; }
                        };
                        pdtls = new DTLSClientProtocol().connect(pskClient, ocf.dtlsTransport());
                        ownerPsk = cpsk;
                        log("owner-PSK DTLS UP with label="+cand[0]+" (0xC037)");
                        break;
                    } catch (Exception ex) {
                        log("  label="+cand[0]+" -> "+ex);
                        try { Thread.sleep(1500); } catch (Exception e2) {}
                    }
                }
                if (pdtls != null) {
                    String uid = jwtUid(cloudBearer);
                    if (uid == null || uid.isEmpty()) uid = jwtUid(jwt);
                    if (uid == null) uid = "";
                    log("cloud uid = '" + uid + "'");
                    securePost(pdtls, Cbor.enc(Cbor.map("tnn", wifiSsid, "cd", wifiPwd==null?"":wifiPwd,
                        "wat", wifiWat, "wet", wifiWet)), "WiFiConfResURI");
                    securePost(pdtls, Cbor.enc(Cbor.map("x.com.samsung.language","en",
                        "x.com.samsung.country","GB")), "DevConfResURI");
                    securePost(pdtls, Cbor.enc(Cbor.map("ac","", "apn",CLOUD_APN, "at",jwt, "att",0, "cis",CLOUD_CIS,
                        "x.com.samsung.clientid",CLOUD_CLIENTID, "x.com.samsung.uid",uid,
                        "x.com.samsung.iatt",2, "x.com.samsung.deployenv","PRD",
                        "x.com.samsung.sadsc", "",
                        "x.com.samsung.refreshtoken","")), "CoapCloudConfResURI");
                    securePost(pdtls, Cbor.enc(Cbor.map("cn", Arrays.asList(1,2))), "EasySetupResURI");
                    cloudProvisioned = true;
                    log("EasySetup posted over OwnerPSK: WiFiConf+DevConf+CoapCloudConf(at=JWT)+cn[1,2]");
                    try { Thread.sleep(18000); } catch (Exception e) {}
                    byte[] es = secureGetRaw(pdtls, "EasySetupResURI");
                    log("ES state resp = " + (es==null?"null":BleOcf.hex(es)));
                } else {
                    log("all owner-PSK labels failed -> cloud skipped (likely BC ECDHE-PSK interop, not the label)");
                }
            }
        } else {
            log("cloud skipped (need Samsung login + Wi-Fi + Bearer); OwnerPSK valid for LocalThings");
        }
        } finally {
            try { if (pdtls != null) pdtls.close(); } catch (Exception e) {}
            try { dtls.close(); } catch (Exception e) {}
            log("DTLS session(s) closed");
        }
    }

    void securePost(DTLSTransport dtls, byte[] payload, String... segs) throws Exception {
        String path = String.join("/", nonq(segs));
        for (int attempt = 1; attempt <= 3; attempt++) {
            byte[] token = new byte[8]; new Random().nextBytes(token);
            byte[] pdu = BleOcf.coapTcp(0x02, token, payload, segs);
            try {
                dtls.send(pdu, 0, pdu.length);
                byte[] buf = new byte[4096];
                int n = dtls.receive(buf, 0, buf.length, 4000);
                if (n <= 0) { log("secure POST /"+path+" -> no resp (try "+attempt+")"); continue; }
                Object[] pr = BleOcf.parseCoapTcp(Arrays.copyOf(buf, n));
                log("secure POST /"+path+" -> "+(pr!=null?pr[0]:"?"));
                return;
            } catch (Exception e) { log("secure POST /"+path+" EXC "+e); return; }
        }
    }

    void secureGet(DTLSTransport dtls, String... segs) throws Exception {
        String path = String.join("/", nonq(segs));
        byte[] token = new byte[8]; new Random().nextBytes(token);
        byte[] pdu = BleOcf.coapTcp(0x01, token, null, segs);
        dtls.send(pdu, 0, pdu.length);
        byte[] buf = new byte[4096];
        int n = dtls.receive(buf, 0, buf.length, 6000);
        if (n <= 0) { log("secure GET /"+path+" -> no resp("+n+")"); return; }
        Object[] pr = BleOcf.parseCoapTcp(Arrays.copyOf(buf, n));
        log("secure GET /"+path+" -> "+(pr!=null?pr[0]:"?"));
    }

    /** Single post that waits up to timeoutMs for the response (the device withholds it until the
     *  physical Volume-Down confirm). Returns true on a response. */
    boolean securePostWait(DTLSTransport dtls, byte[] payload, int timeoutMs, String... segs) throws Exception {
        String path = String.join("/", nonq(segs));
        byte[] token = new byte[8]; new Random().nextBytes(token);
        byte[] pdu = BleOcf.coapTcp(0x02, token, payload, segs);
        dtls.send(pdu, 0, pdu.length);
        byte[] buf = new byte[4096];
        int n = dtls.receive(buf, 0, buf.length, timeoutMs);
        if (n <= 0) { log("secure POST /"+path+" -> no confirm within "+(timeoutMs/1000)+"s"); return false; }
        Object[] pr = BleOcf.parseCoapTcp(Arrays.copyOf(buf, n));
        log("secure POST /"+path+" -> "+(pr!=null?pr[0]:"?")+" (confirmed)");
        return true;
    }

    byte[] secureGetRaw(DTLSTransport dtls, String... segs) throws Exception {
        byte[] token = new byte[8]; new Random().nextBytes(token);
        byte[] pdu = BleOcf.coapTcp(0x01, token, null, segs);
        dtls.send(pdu, 0, pdu.length);
        byte[] buf = new byte[4096];
        int n = dtls.receive(buf, 0, buf.length, 8000);
        if (n <= 0) { log("secure GET /"+String.join("/",nonq(segs))+" -> no resp"); return null; }
        Object[] pr = BleOcf.parseCoapTcp(Arrays.copyOf(buf, n));
        log("secure GET /"+String.join("/",nonq(segs))+" -> "+(pr!=null?pr[0]:"?"));
        return Arrays.copyOf(buf, n);
    }

    String mintJwt(String bearer, String locationId, String roomId){
        if (bearer==null||locationId==null||roomId==null){ log("mintJwt: missing cloud params"); return null; }
        try {
            java.net.URL u = new java.net.URL("https://client.smartthings.com/nexo/auth/jwt");
            javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection)u.openConnection();
            c.setConnectTimeout(15000); c.setReadTimeout(15000); c.setRequestMethod("POST");
            c.setRequestProperty("authorization","Bearer "+bearer);
            c.setRequestProperty("content-type","application/json; charset=UTF-8");
            c.setDoOutput(true);
            String body = "{\"locationId\":\""+locationId+"\",\"roomId\":\""+roomId+"\",\"scope\":[\"iot.device\"]}";
            c.getOutputStream().write(body.getBytes("UTF-8"));
            int code = c.getResponseCode();
            java.io.InputStream is = code<400 ? c.getInputStream() : c.getErrorStream();
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[4096]; int r; while(is!=null && (r=is.read(b))>0) bo.write(b,0,r);
            String resp = new String(bo.toByteArray(),"UTF-8");
            log("nexo/auth/jwt -> HTTP "+code);
            if (code >= 400){ log("jwt err: "+resp.substring(0,Math.min(160,resp.length()))); return null; }
            String jwt = new org.json.JSONObject(resp).optString("jwt","");
            log("JWT minted ("+jwt.length()+" chars)");
            return jwt.isEmpty()?null:jwt;
        } catch (Exception e){ log("mintJwt EXC "+e); return null; }
    }

    // Decode a JWT payload and pull a Samsung/account uid claim (one-login: no device-OAuth).
    String jwtUid(String jwt){
        try {
            if (jwt == null) return null;
            String[] p = jwt.split("\\.");
            if (p.length < 2) return null;
            byte[] pl = android.util.Base64.decode(p[1], android.util.Base64.URL_SAFE|android.util.Base64.NO_PADDING|android.util.Base64.NO_WRAP);
            org.json.JSONObject o = new org.json.JSONObject(new String(pl, "UTF-8"));
            log("jwt claims: " + o.toString());
            for (String k : new String[]{"uid","userId","user_id","sub","cid","suid","saGuid","mobileUID"}) {
                String v = o.optString(k, null);
                if (v != null && !v.isEmpty()) { log("jwt uid via '"+k+"'"); return v; }
            }
        } catch (Exception e){ log("jwtUid err "+e); }
        return null;
    }

    static byte[] rawSecret(TlsSecret s) throws Exception {
        if (s == null) return null;
        for (Class<?> c=s.getClass(); c!=null; c=c.getSuperclass())
            try { java.lang.reflect.Field f=c.getDeclaredField("data"); f.setAccessible(true); return (byte[]) f.get(s); } catch (NoSuchFieldException ig){}
        return null;
    }
    static byte[] grabMaster(TlsContext ctx) throws Exception {
        SecurityParameters spc = ctx.getSecurityParametersConnection();
        if (spc != null) { byte[] m = rawSecret(spc.getMasterSecret()); if (m != null) return m; }
        for (Class<?> c=ctx.getClass(); c!=null; c=c.getSuperclass())
            try { java.lang.reflect.Field f=c.getDeclaredField("securityParametersHandshake"); f.setAccessible(true);
                Object sp=f.get(ctx); if(sp!=null){ Object ms=sp.getClass().getMethod("getMasterSecret").invoke(sp); byte[] m=rawSecret((TlsSecret)ms); if(m!=null) return m; } }
            catch (NoSuchFieldException ig){}
        return null;
    }
}
