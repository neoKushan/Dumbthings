package com.poc.stprov;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** OCF-over-BLE: IoTivity cafragmentation + CoAP-over-TCP (RFC 8323). Confirmed from the app's
 *  btsnoop: srcPort=1, destPort=0, 8-byte token, CoAP/TCP; secure<<7 flags DTLS frames. */
public class BleOcf {

    public static List<byte[]> fragment(byte[] pdu, int frameSize, int srcPort, int destPort, boolean secure) {
        List<byte[]> frames = new ArrayList<>();
        int firstCap = frameSize - 6, contCap = frameSize - 2, off = 0;
        boolean first = true;
        do {
            ByteArrayOutputStream f = new ByteArrayOutputStream();
            f.write((first ? 0x80 : 0x00) | (srcPort & 0x7f));
            f.write((secure ? 0x80 : 0x00) | (destPort & 0x7f));
            int cap;
            if (first) {
                f.write((pdu.length>>24)&0xff); f.write((pdu.length>>16)&0xff);
                f.write((pdu.length>>8)&0xff);  f.write(pdu.length&0xff); cap = firstCap;
            } else cap = contCap;
            int n = Math.min(cap, pdu.length - off);
            if (n > 0) f.write(pdu, off, n);
            off += n; frames.add(f.toByteArray()); first = false;
        } while (off < pdu.length);
        return frames;
    }

    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private int expected = -1;
    public int lastSrc, lastDst; public boolean lastSecure;
    public byte[] feed(byte[] frame) {
        if (frame.length < 2) return null;
        boolean start = (frame[0] & 0x80) != 0;
        lastSrc = frame[0] & 0x7f; lastSecure = (frame[1] & 0x80) != 0; lastDst = frame[1] & 0x7f;
        int hdr = 2;
        if (start) { buf.reset(); if (frame.length < 6) return null;
            expected = ((frame[2]&0xff)<<24)|((frame[3]&0xff)<<16)|((frame[4]&0xff)<<8)|(frame[5]&0xff); hdr = 6; }
        if (frame.length > hdr) buf.write(frame, hdr, frame.length - hdr);
        if (expected >= 0 && buf.size() >= expected) {
            byte[] all = buf.toByteArray(), pdu = new byte[expected];
            System.arraycopy(all, 0, pdu, 0, expected); expected = -1; return pdu;
        }
        return null;
    }
    public void reset(){ buf.reset(); expected = -1; }

    /** CoAP-over-TCP PDU. code: 1=GET,2=POST,3=PUT. segs starting with '?' are Uri-Query. */
    public static byte[] coapTcp(int code, byte[] token, byte[] payload, String... segs) {
        ByteArrayOutputStream opts = new ByteArrayOutputStream();
        int prev = 0;
        for (String s : segs) if (!s.startsWith("?")) { byte[] sb=s.getBytes(); opt(opts, 11-prev, sb); prev=11; }
        if (payload != null) { opt(opts, 12-prev, new byte[]{0x27,0x10}); prev=12; } // Content-Format 10000 (ocf+cbor)
        for (String s : segs) if (s.startsWith("?")) { byte[] sb=s.substring(1).getBytes(); opt(opts, 15-prev, sb); prev=15; }
        byte[] ob = opts.toByteArray();
        int bodyLen = ob.length + (payload!=null ? 1+payload.length : 0);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (bodyLen < 13) o.write((bodyLen<<4)|token.length);
        else if (bodyLen < 269) { o.write((13<<4)|token.length); o.write(bodyLen-13); }
        else { o.write((14<<4)|token.length); o.write(((bodyLen-269)>>8)&0xff); o.write((bodyLen-269)&0xff); }
        o.write(code); o.write(token,0,token.length); o.write(ob,0,ob.length);
        if (payload != null) { o.write(0xff); o.write(payload,0,payload.length); }
        return o.toByteArray();
    }
    static void opt(ByteArrayOutputStream o, int delta, byte[] val) {
        int len = val.length;
        int db = delta<13?delta:(delta<269?13:14), lb = len<13?len:(len<269?13:14);
        o.write((db<<4)|lb);
        if (db==13) o.write(delta-13); else if (db==14){ o.write((delta-269)>>8); o.write((delta-269)&0xff); }
        if (lb==13) o.write(len-13); else if (lb==14){ o.write((len-269)>>8); o.write((len-269)&0xff); }
        o.write(val,0,len);
    }

    /** Parse a CoAP-over-TCP message -> {codeStr, payload}. */
    public static Object[] parseCoapTcp(byte[] p) {
        if (p == null || p.length < 2) return null;
        int ln=(p[0]&0xff)>>4, tkl=p[0]&0xf, i=1, extlen=0;
        if (ln==13){ extlen=p[i]&0xff; i+=1; } else if (ln==14){ extlen=((p[i]&0xff)<<8)|(p[i+1]&0xff); i+=2; }
        if (i>=p.length) return null;
        int code=p[i]&0xff; i+=1; i+=tkl;   // skip token
        while (i<p.length) { if ((p[i]&0xff)==0xff){ i++; break; }
            int d=(p[i]>>4)&0xf, l=p[i]&0xf; i++;
            if(d==13){d=p[i]+13;i++;} else if(d==14){d=((p[i]&0xff)<<8)+269;i+=2;}
            if(l==13){l=(p[i]&0xff)+13;i++;} else if(l==14){l=((p[i]&0xff)<<8)+269;i+=2;}
            i+=l;
        }
        byte[] pay = i<=p.length ? java.util.Arrays.copyOfRange(p, Math.min(i,p.length), p.length) : new byte[0];
        return new Object[]{ (code>>5)+"."+String.format("%02d",code&0x1f), pay };
    }

    public static String hex(byte[] b){ StringBuilder s=new StringBuilder(); if(b!=null) for(byte x:b) s.append(String.format("%02x",x)); return s.toString(); }
    public static String ascii(byte[] b){ StringBuilder s=new StringBuilder(); if(b!=null) for(byte x:b) s.append((x>=32&&x<127)?(char)x:'.'); return s.toString(); }
}
