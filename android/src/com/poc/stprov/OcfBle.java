package com.poc.stprov;

import android.bluetooth.*;
import android.content.Context;
import android.util.Log;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.tls.DatagramTransport;

/** OCF-over-BLE transport: BLE GATT + IoTivity cafragmentation + CoAP-over-TCP,
 *  with a blocking request API (unsecured) and a BC DatagramTransport over secure frames (DTLS). */
public class OcfBle {
    public interface Logger { void log(String s); }
    static final UUID SVC   = UUID.fromString("ade3d529-c784-4f63-a987-eb69f70ee816");
    static final UUID WRITE = UUID.fromString("ad7b334f-4637-4b86-90b6-9d787f03d218");
    static final UUID NOTIFY= UUID.fromString("e9241982-4580-42c4-8831-95048216b256");
    static final UUID CCCD  = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    final Context ctx; final Logger lg; final BluetoothDevice dev;
    BluetoothGatt gatt; BluetoothGattCharacteristic writeCh, notifyCh;
    int frameSize = 20, mid = 0x100, srcPort = 1;
    public byte[] deviceUuid;

    final BleOcf reUnsec = new BleOcf(), reSec = new BleOcf();
    final BlockingQueue<byte[]> unsecQ = new LinkedBlockingQueue<>();
    final BlockingQueue<byte[]> dtlsQ  = new LinkedBlockingQueue<>();
    final LinkedBlockingQueue<Integer> connected = new LinkedBlockingQueue<>();
    final java.util.concurrent.atomic.AtomicBoolean discovering = new java.util.concurrent.atomic.AtomicBoolean(false);
    final java.util.concurrent.atomic.AtomicBoolean setupOnce = new java.util.concurrent.atomic.AtomicBoolean(false);
    final java.util.concurrent.atomic.AtomicBoolean readyOnce = new java.util.concurrent.atomic.AtomicBoolean(false);
    final Semaphore writeSem = new Semaphore(1);

    public OcfBle(Context c, Logger l, BluetoothDevice d){ ctx=c; lg=l; dev=d; }
    void log(String s){ if(lg!=null) lg.log(s); else Log.i("STPROV", s); }

    public void connect() throws Exception {
        for (int attempt=1; attempt<=5; attempt++) {
            discovering.set(false); setupOnce.set(false); readyOnce.set(false); connected.clear(); reUnsec.reset(); reSec.reset();
            gatt = dev.connectGatt(ctx, false, cb, BluetoothDevice.TRANSPORT_LE);
            Integer st = connected.poll(12, TimeUnit.SECONDS);
            if (st != null && st == 0) return;
            log("connect attempt "+attempt+" st="+st+"; waiting ~10s for the bar to release the old session");
            try{ gatt.disconnect(); gatt.close(); }catch(Exception e){}
            Thread.sleep(10000);
        }
        throw new Exception("BLE connect/setup failed after retries");
    }
    void refresh(BluetoothGatt g){ try{ g.getClass().getMethod("refresh").invoke(g); }catch(Exception e){} }
    public void close(){ try{ gatt.disconnect(); gatt.close(); }catch(Exception e){} }

    final BluetoothGattCallback cb = new BluetoothGattCallback(){
        @Override public void onConnectionStateChange(BluetoothGatt g,int s,int ns){
            log("conn state="+s+" new="+ns);
            if(ns==BluetoothProfile.STATE_CONNECTED){ try{ g.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH);}catch(Exception e){} g.requestMtu(247); }
            else if(ns==BluetoothProfile.STATE_DISCONNECTED){ log("BLE disconnected"); connected.offer(-1); }
        }
        @Override public void onMtuChanged(BluetoothGatt g,int mtu,int s){ frameSize=Math.min(mtu-3,512); if(!discovering.compareAndSet(false,true))return; log("mtu="+mtu+" frameSize="+frameSize); refresh(g); g.discoverServices(); }
        @Override public void onServicesDiscovered(BluetoothGatt g,int s){
            if(!setupOnce.compareAndSet(false,true)) return;
            log("services discovered status="+s+" n="+g.getServices().size());
            BluetoothGattService sv=g.getService(SVC);
            if(sv==null){ log("no OCF service"); connected.offer(-2); return; }
            writeCh=sv.getCharacteristic(WRITE); notifyCh=sv.getCharacteristic(NOTIFY);
            if(writeCh==null||notifyCh==null){ log("missing OCF chars"); connected.offer(-3); return; }
            g.setCharacteristicNotification(notifyCh,true);
            int props=notifyCh.getProperties();
            BluetoothGattDescriptor d=notifyCh.getDescriptor(CCCD);
            if(d==null){ log("CCCD descriptor MISSING props=0x"+Integer.toHexString(props)+"; proceeding"); connected.offer(0); return; }
            byte[] val=((props & BluetoothGattCharacteristic.PROPERTY_NOTIFY)!=0)
                ? BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                : BluetoothGattDescriptor.ENABLE_INDICATION_VALUE;
            d.setValue(val); boolean ok=g.writeDescriptor(d);
            log("CCCD write props=0x"+Integer.toHexString(props)+" mode="+(val[0]==1?"NOTIFY":"INDICATE")+" initiated="+ok);
            // fallback: if the descriptor-write ACK never arrives, proceed anyway and let the first GET prove the link
            new Thread(()->{ try{Thread.sleep(5000);}catch(Exception e){} if(readyOnce.compareAndSet(false,true)){ log("CCCD ack timeout; proceeding to GET"); connected.offer(0);} }).start();
        }
        @Override public void onDescriptorWrite(BluetoothGatt g,BluetoothGattDescriptor d,int s){ if(readyOnce.compareAndSet(false,true)){ log("OCF ready (ack="+s+")"); connected.offer(0);} }
        @Override public void onCharacteristicWrite(BluetoothGatt g,BluetoothGattCharacteristic c,int s){ writeSem.release(); }
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c,byte[] v){ rx(v); }
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c){ rx(c.getValue()); }
    };

    void rx(byte[] frame){
        boolean sec = (frame.length>=2) && ((frame[1]&0x80)!=0);
        byte[] pdu = (sec?reSec:reUnsec).feed(frame);
        if (pdu!=null){ if(sec) dtlsQ.offer(pdu); else unsecQ.offer(pdu); }
    }

    void writeFrames(byte[] pdu, boolean secure) throws Exception {
        int fi = 0;
        for (byte[] f : BleOcf.fragment(pdu, frameSize, srcPort, 0, secure)){
            if(!writeSem.tryAcquire(5, TimeUnit.SECONDS)) throw new Exception("BLE write stalled");
            writeCh.setValue(f); writeCh.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            boolean ok = false;
            // writeCharacteristic returns false while the stack is still busy with the prior op;
            // no callback fires in that case, so keep the permit and retry the same fragment.
            for (int a = 0; a < 12 && !ok; a++){
                ok = gatt.writeCharacteristic(writeCh);
                if(!ok){ try{ Thread.sleep(50); }catch(Exception e){} }
            }
            if(!ok){ writeSem.release(); throw new Exception("writeCharacteristic rejected (frag "+fi+" len="+f.length+")"); }
            fi++;
        }
    }

    byte[] token(){ byte[] t=new byte[8]; new Random().nextBytes(t); return t; }

    /** Unsecured CoAP-over-TCP request; returns the response PDU. code: 0x01 GET, 0x02 POST. */
    public byte[] request(int code, byte[] payload, String... segs) throws Exception {
        byte[] pdu = BleOcf.coapTcp(code, token(), payload, segs);
        unsecQ.clear();
        writeFrames(pdu, false);
        byte[] resp = unsecQ.poll(10, TimeUnit.SECONDS);
        if (resp==null) throw new Exception("no response to /"+String.join("/",segs));
        return resp;
    }

    /** Drop buffered DTLS records so a fresh handshake (owner-PSK reconnect) starts clean. */
    public void resetDtls(){ dtlsQ.clear(); }

    /** BC DatagramTransport carrying DTLS records in secure ble_ocf frames. */
    public DatagramTransport dtlsTransport(){
        return new DatagramTransport(){
            public int getReceiveLimit(){ return 1400; }
            public int getSendLimit(){ return frameSize*8; }
            public int receive(byte[] buf,int off,int len,int waitMs) throws java.io.IOException {
                try{ byte[] p=dtlsQ.poll(waitMs,TimeUnit.MILLISECONDS); if(p==null) return -1; int n=Math.min(len,p.length); System.arraycopy(p,0,buf,off,n); return n; }
                catch(InterruptedException e){ return -1; }
            }
            public void send(byte[] buf,int off,int len) throws java.io.IOException {
                try{ byte[] rec=Arrays.copyOfRange(buf,off,off+len); writeFrames(rec,true); }catch(Exception e){ throw new java.io.IOException(e); }
            }
            public void close(){}
        };
    }
}
