package com.poc.stprov;

import java.io.ByteArrayOutputStream;
import java.util.*;

/** Minimal CBOR for OCF payloads (maps, arrays, text/byte strings, ints, bool, nil; definite + indefinite). */
public class Cbor {
    static final Object BREAK = new Object();

    // ---- encode (always definite-length) ----
    public static byte[] enc(Object o) { ByteArrayOutputStream b = new ByteArrayOutputStream(); w(b, o); return b.toByteArray(); }
    @SuppressWarnings("unchecked")
    static void w(ByteArrayOutputStream b, Object o) {
        if (o == null) b.write(0xf6);
        else if (o instanceof Boolean) b.write(((Boolean)o) ? 0xf5 : 0xf4);
        else if (o instanceof Integer || o instanceof Long) {
            long v = ((Number)o).longValue();
            if (v >= 0) t(b, 0, v); else t(b, 1, -1 - v);
        } else if (o instanceof String) { byte[] s = ((String)o).getBytes(); t(b, 3, s.length); b.writeBytes(s); }
        else if (o instanceof byte[]) { byte[] s = (byte[])o; t(b, 2, s.length); b.writeBytes(s); }
        else if (o instanceof Map) { Map<Object,Object> m=(Map<Object,Object>)o; t(b,5,m.size()); for (Map.Entry<Object,Object> e:m.entrySet()){ w(b,e.getKey()); w(b,e.getValue()); } }
        else if (o instanceof List) { List<Object> l=(List<Object>)o; t(b,4,l.size()); for (Object x:l) w(b,x); }
        else throw new IllegalArgumentException("cbor: " + o.getClass());
    }
    static void t(ByteArrayOutputStream b, int major, long v) {
        int mt = major << 5;
        if (v < 24) b.write(mt | (int)v);
        else if (v < 256) { b.write(mt|24); b.write((int)v); }
        else if (v < 65536) { b.write(mt|25); b.write((int)(v>>8)); b.write((int)v); }
        else { b.write(mt|26); b.write((int)(v>>24)); b.write((int)(v>>16)); b.write((int)(v>>8)); b.write((int)v); }
    }

    // ---- decode ----
    int p; byte[] d;
    public static Object dec(byte[] data) { Cbor c = new Cbor(); c.d = data; c.p = 0; return c.r(); }
    Object r() {
        int ib = d[p++] & 0xff, major = ib >> 5, ai = ib & 0x1f;
        if (major == 7) { if (ai==31) return BREAK; return ai==20?Boolean.FALSE:ai==21?Boolean.TRUE:null; }
        boolean indef = (ai == 31);
        long val = ai;
        if (ai==24) val=d[p++]&0xff;
        else if (ai==25){ val=((d[p]&0xff)<<8)|(d[p+1]&0xff); p+=2; }
        else if (ai==26){ val=((long)(d[p]&0xff)<<24)|((d[p+1]&0xff)<<16)|((d[p+2]&0xff)<<8)|(d[p+3]&0xff); p+=4; }
        else if (ai==27){ val=0; for(int k=0;k<8;k++) val=(val<<8)|(d[p++]&0xff); }
        switch (major) {
            case 0: return val;
            case 1: return -1 - val;
            case 2: { byte[] s=Arrays.copyOfRange(d,p,p+(int)val); p+=val; return s; }
            case 3: { String s=new String(d,p,(int)val); p+=val; return s; }
            case 4: { List<Object> l=new ArrayList<>();
                if (indef){ Object x; while((x=r())!=BREAK) l.add(x); } else for(int i=0;i<val;i++) l.add(r());
                return l; }
            case 5: { Map<Object,Object> m=new LinkedHashMap<>();
                if (indef){ Object k; while((k=r())!=BREAK) m.put(k,r()); } else for(int i=0;i<val;i++){ Object k=r(); m.put(k,r()); }
                return m; }
            default: throw new RuntimeException("cbor major " + major);
        }
    }
    public static Map<String,Object> map(Object... kv) {
        LinkedHashMap<String,Object> m = new LinkedHashMap<>();
        for (int i=0;i<kv.length;i+=2) m.put((String)kv[i], kv[i+1]);
        return m;
    }
}
