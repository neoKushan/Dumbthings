package com.poc.stprov;

import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.*;
import android.bluetooth.le.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import android.util.Log;
import android.widget.*;
import java.util.*;
import org.json.*;

public class MainActivity extends Activity implements OcfBle.Logger, Otm.Log {
    static final String TAG = "STPROV";
    static final android.os.ParcelUuid OCF_SVC = android.os.ParcelUuid.fromString("ade3d529-c784-4f63-a987-eb69f70ee816");
    static final String PREFS = "stprov", KEY_PAIRED = "paired";

    TextView log; EditText result; Button bearerBtn; BluetoothLeScanner scanner; AlertDialog promptDialog;
    final Handler ui = new Handler(Looper.getMainLooper());
    final java.util.concurrent.atomic.AtomicBoolean busy = new java.util.concurrent.atomic.AtomicBoolean(false);
    final LinkedHashMap<String,BluetoothDevice> found = new LinkedHashMap<>();
    String wifiSsid, wifiPwd;
    boolean verifyMode;

    public void log(String s){ Log.i(TAG, s); ui.post(() -> log.append(s + "\n")); }
    /** Persistent, non-cancelable modal while the device waits for its physical confirm.
     *  Call with null/empty to dismiss. */
    public void prompt(String s){ Log.i(TAG, "PROMPT: " + s); ui.post(() -> {
        if (promptDialog != null) { try { promptDialog.dismiss(); } catch (Exception e) {} promptDialog = null; }
        if (s == null || s.isEmpty()) return;
        result.setText(">>> " + s + " <<<");
        promptDialog = new AlertDialog.Builder(this)
            .setTitle("Confirm on the device").setMessage(s).setCancelable(false).show();
        try { ((android.os.Vibrator)getSystemService(VIBRATOR_SERVICE)).vibrate(600); } catch (Exception e) {}
    }); }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this); ll.setOrientation(LinearLayout.VERTICAL); ll.setPadding(12,12,12,12);
        bearerBtn = new Button(this); bearerBtn.setText("1. SMARTTHINGS LOGIN");
        Button scan = new Button(this); scan.setText("2. SCAN & PAIR OCF DEVICE");
        Button paired = new Button(this); paired.setText("SAVED DEVICES (re-copy PSK)");
        Button verify = new Button(this); verify.setText("3. VERIFY OWNED (read doxm only)");
        result = new EditText(this); result.setTextSize(11); result.setKeyListener(null); result.setHint("result will appear here");
        Button copy = new Button(this); copy.setText("COPY RESULT");
        log = new TextView(this); log.setTextSize(9); log.setPadding(4,12,4,4);
        ll.addView(bearerBtn); ll.addView(scan); ll.addView(verify); ll.addView(paired); ll.addView(result); ll.addView(copy); ll.addView(log);
        sv.addView(ll); setContentView(sv);
        bearerBtn.setOnClickListener(v -> startActivityForResult(new Intent(this, StLoginActivity.class), 3));
        scan.setOnClickListener(v -> { verifyMode = false; maybeScan(); });
        verify.setOnClickListener(v -> { verifyMode = true; maybeScan(); });
        paired.setOnClickListener(v -> showPaired());
        copy.setOnClickListener(v -> copyText(result.getText().toString()));
        loadLogin();
    }

    @Override protected void onActivityResult(int rc, int res, Intent data) {
        if (rc == 3 && res == RESULT_OK && data != null) {
            String bt = data.getStringExtra("bearer");
            if (bt != null) { toast("bearer captured; fetching location/room..."); new Thread(() -> saveCloudBearer(bt)).start(); }
        }
    }
    void loadLogin() {
        SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        wifiSsid = sp.getString("wifiSsid", null); wifiPwd = sp.getString("wifiPwd", null);
        if (new java.io.File(getFilesDir(), "st_cloud.txt").exists())
            ui.post(() -> bearerBtn.setText("\u2713 Cloud bearer set"));
    }

    void saveCloudBearer(String bearer) {
        try {
            String loc = firstId("https://api.smartthings.com/v1/locations", bearer, "locationId");
            if (loc == null) { log("cloud bearer: no locations (token valid?)"); toast("bearer rejected"); return; }
            String room = firstId("https://api.smartthings.com/v1/locations/" + loc + "/rooms", bearer, "roomId");
            if (room == null) room = loc;
            java.io.FileWriter fw = new java.io.FileWriter(new java.io.File(getFilesDir(), "st_cloud.txt"));
            fw.write(bearer + "\n" + loc + "\n" + room + "\n"); fw.close();
            log("cloud bearer saved (loc=" + loc + " room=" + room + ")");
            ui.post(() -> bearerBtn.setText("\u2713 Cloud bearer set"));
        } catch (Exception e) { log("saveCloudBearer err " + e); toast("error"); }
    }
    String firstId(String url, String bearer, String key) throws Exception {
        javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection) new java.net.URL(url).openConnection();
        c.setConnectTimeout(12000); c.setReadTimeout(12000);
        c.setRequestProperty("authorization", "Bearer " + bearer);
        int code = c.getResponseCode();
        if (code >= 400) { log("GET " + url + " -> " + code); return null; }
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        java.io.InputStream is = c.getInputStream(); byte[] bb = new byte[4096]; int r;
        while ((r = is.read(bb)) > 0) bo.write(bb, 0, r);
        org.json.JSONArray items = new org.json.JSONObject(new String(bo.toByteArray(), "UTF-8")).optJSONArray("items");
        if (items == null || items.length() == 0) return null;
        return items.getJSONObject(0).optString(key, null);
    }
    org.json.JSONArray devicesJson(String bearer) throws Exception {
        javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection) new java.net.URL("https://api.smartthings.com/v1/devices").openConnection();
        c.setConnectTimeout(12000); c.setReadTimeout(12000);
        c.setRequestProperty("authorization", "Bearer " + bearer);
        if (c.getResponseCode() != 200) return null;
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        java.io.InputStream is = c.getInputStream(); byte[] bb = new byte[4096]; int r;
        while ((r = is.read(bb)) > 0) bo.write(bb, 0, r);
        return new org.json.JSONObject(new String(bo.toByteArray(), "UTF-8")).optJSONArray("items");
    }
    java.util.Set<String> cloudDeviceIds(String bearer) {
        java.util.HashSet<String> s = new java.util.HashSet<>();
        try { org.json.JSONArray items = devicesJson(bearer);
            if (items != null) for (int i = 0; i < items.length(); i++) {
                String id = items.getJSONObject(i).optString("deviceId", null);
                if (id != null) s.add(id);
            }
        } catch (Exception e) { log("cloudDeviceIds err " + e); }
        return s;
    }
    // poll the cloud until a device id not in 'before' shows up (the bar just registered)
    String pollForNewDevice(String bearer, java.util.Set<String> before, int tries, int delayMs) {
        for (int t = 0; t < tries; t++) {
            try { Thread.sleep(delayMs); } catch (Exception e) {}
            try { org.json.JSONArray items = devicesJson(bearer);
                if (items != null) for (int i = 0; i < items.length(); i++) {
                    org.json.JSONObject o = items.getJSONObject(i);
                    String id = o.optString("deviceId", null);
                    if (id != null && !before.contains(id)) {
                        String nm = o.optString("label", o.optString("name", "device"));
                        log("cloud device appeared: " + id + " (" + nm + ")");
                        return nm;
                    }
                }
            } catch (Exception e) { log("poll err " + e); }
        }
        return null;
    }
    void showFieldsDialog(String title, java.util.LinkedHashMap<String,String> fields, String deviceUuid) {
        ui.post(() -> {
            LinearLayout box = new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL);
            box.setPadding(36,8,36,8);
            for (java.util.Map.Entry<String,String> e : fields.entrySet()) {
                final String k = e.getKey(); final String v = e.getValue()==null?"":e.getValue();
                final boolean hl = k.equals("Owner PSK") || k.equals("ip");
                TextView lbl = new TextView(this);
                lbl.setText(hl ? k + "  \u2605 LocalThings needs this" : k);
                lbl.setTextSize(11); lbl.setPadding(0,14,0,2);
                if (hl) { lbl.setTypeface(null, android.graphics.Typeface.BOLD); lbl.setTextColor(0xFF4CAF50); }
                final TextView val = new TextView(this); val.setText(v.isEmpty()?"\u2014":v);
                val.setTextSize(hl ? 16 : 14); val.setTextIsSelectable(true);
                val.setTypeface(android.graphics.Typeface.MONOSPACE, hl ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
                if (hl) val.setTextColor(0xFF4CAF50);
                val.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
                final Button btn = new Button(this);
                LinearLayout row = new LinearLayout(this); row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(android.view.Gravity.CENTER_VERTICAL);
                if (hl) { row.setBackgroundColor(0x224CAF50); row.setPadding(8,4,8,4); }
                if (k.equals("ip") && v.isEmpty() && deviceUuid != null) {
                    btn.setText("FIND");
                    btn.setOnClickListener(x -> {
                        btn.setEnabled(false); val.setText("searching\u2026");
                        new Thread(() -> { final String ip = discoverIp(deviceUuid); ui.post(() -> {
                            if (ip != null) { val.setText(ip); btn.setText("COPY"); btn.setEnabled(true);
                                btn.setOnClickListener(y -> copyLabeled("ip", ip)); }
                            else { val.setText("not found"); btn.setText("RETRY"); btn.setEnabled(true); }
                        }); }).start();
                    });
                } else {
                    btn.setText("COPY"); btn.setEnabled(!v.isEmpty());
                    btn.setOnClickListener(x -> copyLabeled(k, v));
                }
                row.addView(val); row.addView(btn);
                box.addView(lbl); box.addView(row);
            }
            ScrollView sc = new ScrollView(this); sc.addView(box);
            new AlertDialog.Builder(this).setTitle(title).setView(sc)
                .setPositiveButton("Copy all", (d,w) -> copyText(renderMap(fields)))
                .setNegativeButton("Close", null).show();
        });
    }
    void copyLabeled(String k, String v) {
        ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText(k, v));
        toast("copied " + k);
    }
    static String renderMap(java.util.LinkedHashMap<String,String> f) {
        StringBuilder sb = new StringBuilder("=== Home Assistant LocalThings ===\n");
        for (java.util.Map.Entry<String,String> e : f.entrySet())
            sb.append(e.getKey()).append(": ").append(e.getValue()==null?"":e.getValue()).append("\n");
        return sb.toString();
    }
    // OCF LAN discovery: multicast GET /oic/res; the reply whose payload contains our device
    // UUID came from the device, so its datagram source IP is the device's LAN IP.
    String discoverIp(String deviceUuid) {
        android.net.wifi.WifiManager.MulticastLock lock = null; java.net.DatagramSocket sock = null;
        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            try { lock = wm.createMulticastLock("stprov"); lock.acquire(); } catch (Exception e) {}
            sock = new java.net.DatagramSocket(); sock.setSoTimeout(700);
            byte[][] reqs = coapVariants();
            java.net.InetAddress grp = java.net.InetAddress.getByName("224.0.1.187");
            String want = deviceUuid.toLowerCase();
            long end = System.currentTimeMillis() + 5000;
            int sent = 0, got = 0;
            for (int round = 0; round < 5 && System.currentTimeMillis() < end; round++) {
                for (byte[] req : reqs) { sock.send(new java.net.DatagramPacket(req, req.length, grp, 5683)); sent++; }
                while (System.currentTimeMillis() < end) {
                    java.net.DatagramPacket resp = new java.net.DatagramPacket(new byte[8192], 8192);
                    try { sock.receive(resp); } catch (java.net.SocketTimeoutException te) { break; }
                    got++;
                    String ip = resp.getAddress().getHostAddress();
                    String body = new String(resp.getData(), 0, resp.getLength(), "ISO-8859-1").toLowerCase();
                    log("  disc reply from " + ip + " len=" + resp.getLength() + " match=" + body.contains(want));
                    log("    raw[" + Math.min(resp.getLength(),64) + "]=" + BleOcf.hex(java.util.Arrays.copyOf(resp.getData(), Math.min(resp.getLength(),64))));
                    if (body.contains(want)) { log("LAN IP for device: " + ip); return ip; }
                }
            }
            log("discoverIp: sent=" + sent + " replies=" + got + " (no uuid match)");
        } catch (Exception e) { log("discoverIp err " + e); }
        finally { try { if (sock!=null) sock.close(); } catch (Exception e){} try { if (lock!=null) lock.release(); } catch (Exception e){} }
        log("discoverIp: device did not answer multicast");
        return null;
    }
    byte[][] coapVariants() {
        // OCF stacks differ on content-format negotiation; try bare, application/cbor, and ocf+cbor.
        return new byte[][]{
            coapReq(0x34, -1, false),      // bare GET /oic/res
            coapReq(0x35, 60, false),      // Accept: application/cbor (60)
            coapReq(0x36, 10000, true),    // Accept: application/vnd.ocf+cbor (10000) + OCF version
        };
    }
    byte[] coapReq(int mid2, int accept, boolean ocfVer) {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        b.write(0x50); b.write(0x01); b.write(0x12); b.write(mid2 & 0xFF);  // NON GET, msg id
        b.write(0xB3); b.write('o'); b.write('i'); b.write('c');            // Uri-Path "oic"
        b.write(0x03); b.write('r'); b.write('e'); b.write('s');            // Uri-Path "res"
        if (accept >= 0 && accept < 256) { b.write(0x61); b.write(accept); }
        else if (accept >= 256) { b.write(0x62); b.write((accept>>8)&0xFF); b.write(accept&0xFF); }
        if (ocfVer) { b.write(0xE2); b.write(0x06); b.write(0xE3); b.write(0x08); b.write(0x00); } // OCF-Content-Format-Version 2048
        return b.toByteArray();
    }
    void pairWithWifi(BluetoothDevice dev) {
        if (!hasBearer()) { new Thread(() -> runOtm(dev)).start(); return; }  // local-only
        EditText ssid = new EditText(this); ssid.setHint("Wi-Fi SSID");
        ssid.setText(wifiSsid != null && !wifiSsid.isEmpty() ? wifiSsid : currentSsid());
        EditText pwd = new EditText(this); pwd.setHint("Wi-Fi password");
        pwd.setText(wifiPwd != null ? wifiPwd : "");
        LinearLayout box = new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(40,20,40,0); box.addView(ssid); box.addView(pwd);
        new AlertDialog.Builder(this).setTitle("Wi-Fi for cloud registration").setView(box)
            .setPositiveButton("Pair + register", (d,w) -> {
                wifiSsid = ssid.getText().toString().trim(); wifiPwd = pwd.getText().toString();
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString("wifiSsid", wifiSsid).putString("wifiPwd", wifiPwd).apply();
                new Thread(() -> runOtm(dev)).start();
            })
            .setNegativeButton("PSK only (no cloud)", (d,w) -> { wifiSsid = null; new Thread(() -> runOtm(dev)).start(); })
            .show();
    }
    String currentSsid() {
        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            String s = wm.getConnectionInfo().getSSID();
            if (s != null) return s.replaceAll("^\"|\"$", "");
        } catch (Exception e) {}
        return "";
    }

    void copyText(String s){ ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE))
        .setPrimaryClip(ClipData.newPlainText("stprov", s)); toast("copied"); }
    void toast(String s){ ui.post(() -> Toast.makeText(this, s, Toast.LENGTH_SHORT).show()); }
    void setResult(String s){ ui.post(() -> result.setText(s)); }
    boolean hasBearer(){ return new java.io.File(getFilesDir(), "st_cloud.txt").exists(); }

    void maybeScan() {
        if (!hasBearer()) {
            new AlertDialog.Builder(this)
                .setTitle("Not signed in to SmartThings")
                .setMessage("Without the SmartThings login this provisions LOCAL control only — the bar won't be cloud-registered, so its media/networkaudio resources stay hidden. Continue local-only?")
                .setPositiveButton("Continue local-only", (d,w) -> ensurePerms())
                .setNegativeButton("Cancel", null).show();
        } else ensurePerms();
    }

    void ensurePerms() {
        List<String> need = new ArrayList<>();
        for (String p : new String[]{android.Manifest.permission.BLUETOOTH_SCAN,
                android.Manifest.permission.BLUETOOTH_CONNECT, android.Manifest.permission.ACCESS_FINE_LOCATION})
            if (checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) need.add(p);
        if (!need.isEmpty()) { requestPermissions(need.toArray(new String[0]), 1); return; }
        scan();
    }
    @Override public void onRequestPermissionsResult(int rc, String[] p, int[] g) { scan(); }

    void scan() {
        if (!busy.compareAndSet(false, true)) return;
        found.clear();
        log("scanning for OCF devices (8s) ...");
        BluetoothManager bm = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        scanner = bm.getAdapter().getBluetoothLeScanner();
        scanner.startScan(null, new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), scanCb);
        ui.postDelayed(() -> { try { scanner.stopScan(scanCb);} catch (Exception e){} busy.set(false); showPicker(); }, 8000);
    }

    final ScanCallback scanCb = new ScanCallback() {
        @Override public void onScanResult(int t, ScanResult r) {
            ScanRecord rec = r.getScanRecord();
            String name = rec != null && rec.getDeviceName() != null ? rec.getDeviceName() : r.getDevice().getName();
            boolean ocf = rec != null && rec.getServiceUuids() != null && rec.getServiceUuids().contains(OCF_SVC);
            boolean named = name != null && (name.startsWith("[") || name.toLowerCase().contains("samsung"));
            if (!ocf && !named) return;
            String addr = r.getDevice().getAddress();
            synchronized (found) {
                if (!found.containsKey(addr)) {
                    found.put(addr, r.getDevice());
                    log("  • " + (name != null ? name : addr) + "  " + addr + (ocf ? "  [OCF]" : "") + "  rssi=" + r.getRssi());
                }
            }
        }
        @Override public void onScanFailed(int e) { log("scan failed " + e); busy.set(false); }
    };

    void showPicker() {
        ui.post(() -> {
            if (found.isEmpty()) { toast("no OCF devices found"); return; }
            List<BluetoothDevice> devs = new ArrayList<>(found.values());
            java.util.Collections.sort(devs, (a, b) ->
                String.valueOf(a.getName()).compareToIgnoreCase(String.valueOf(b.getName())));
            String[] labels = new String[devs.size()];
            for (int i = 0; i < devs.size(); i++) {
                BluetoothDevice d = devs.get(i);
                labels[i] = (d.getName() != null ? d.getName() : "?") + "\n" + d.getAddress();
            }
            new AlertDialog.Builder(this).setTitle("Pick device to pair")
                .setItems(labels, (dlg, i) -> {
                    BluetoothDevice dev = devs.get(i);
                    if (verifyMode) { log("verify " + dev.getAddress()); new Thread(() -> verifyOwned(dev)).start(); }
                    else { log("pairing " + dev.getAddress()); pairWithWifi(dev); }
                }).show();
        });
    }

    // read-only ownership check: connect + GET /oic/sec/doxm, no writes (safe, won't revert)
    void verifyOwned(BluetoothDevice dev) {
        OcfBle ocf = new OcfBle(this, this, dev);
        try {
            ocf.connect();
            Object[] p = BleOcf.parseCoapTcp(ocf.request(0x01, null, "oic","sec","doxm"));
            @SuppressWarnings("unchecked")
            java.util.Map<Object,Object> doxm = (java.util.Map<Object,Object>) Cbor.dec((byte[]) p[1]);
            String owned = String.valueOf(doxm.get("owned"));
            String devowner = String.valueOf(doxm.get("devowneruuid"));
            log("VERIFY: owned=" + owned + " devowneruuid=" + devowner);
            setResult("=== VERIFY OWNED ===\nowned:         " + owned
                + "\ndevowneruuid:  " + devowner + "\n(owned=true + our owner_id => ownership stuck)");
        } catch (Exception e) {
            log("VERIFY FAILED: " + e);
        } finally { ocf.close(); }
    }

    void runOtm(BluetoothDevice dev) {
        OcfBle ocf = new OcfBle(this, this, dev);
        try {
            ocf.connect();
            Otm otm = new Otm(ocf, this);
            otm.wifiSsid = wifiSsid; otm.wifiPwd = wifiPwd;
            try {
                java.io.File cf = new java.io.File(getFilesDir(), "st_cloud.txt");
                if (cf.exists()) {
                    java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(cf));
                    otm.cloudBearer = br.readLine(); otm.cloudLocationId = br.readLine(); otm.cloudRoomId = br.readLine();
                    br.close();
                    log("cloud params loaded (bearer " + (otm.cloudBearer==null?0:otm.cloudBearer.length()) + "ch, loc " + otm.cloudLocationId + ")");
                }
            } catch (Exception e) { log("cloud file read err " + e); }
            if (wifiSsid != null) { int[] s = wifiSec(wifiSsid); otm.wifiWat = s[0]; otm.wifiWet = s[1];
                log("wifi sec: wat=" + s[0] + " wet=" + s[1]); }
            java.util.Set<String> beforeIds = (otm.cloudBearer != null && !otm.cloudBearer.isEmpty())
                ? cloudDeviceIds(otm.cloudBearer) : null;
            otm.run("conmfgcert");
            String psk = BleOcf.hex(otm.ownerPsk);
            String label = dev.getName() != null ? dev.getName() : dev.getAddress();
            savePaired(label, otm.deviceUuid, otm.ownerUuid.toString(), psk, dev.getAddress(), otm.cloudProvisioned);
            String details = render(label, otm.deviceUuid, otm.ownerUuid.toString(), psk, dev.getAddress(), otm.cloudProvisioned);
            setResult(details);
            log("DONE — saved to SAVED DEVICES");
            String status;
            if (otm.cloudProvisioned && beforeIds != null) {
                setResult(details + "\nConfirming in SmartThings (up to 45s)...");
                log("confirming registration via SmartThings cloud...");
                String newName = pollForNewDevice(otm.cloudBearer, beforeIds, 9, 5000);
                status = (newName != null)
                    ? "\u2713 Added to SmartThings as \"" + newName + "\""
                    : "\u26A0 Provisioned, but not yet visible in SmartThings";
            } else {
                status = "Local-only \u2014 PSK ready for Home Assistant";
            }
            java.util.LinkedHashMap<String,String> fields = new java.util.LinkedHashMap<>();
            fields.put("ip", ""); fields.put("Owner PSK", psk);
            fields.put("name", label); fields.put("device_id", otm.deviceUuid);
            fields.put("owner_id", otm.ownerUuid.toString()); fields.put("ble_mac", dev.getAddress());
            showFieldsDialog(status, fields, otm.deviceUuid);
        } catch (Exception e) {
            log("OTM FAILED: " + e);
            for (StackTraceElement s : e.getStackTrace()) log("  at " + s);
        } finally { ocf.close(); }
    }

    // The device auto-detects the AP's auth from the supplied password. The real SmartThings
    // app sends wat=0 (NONE) + wet=4 (AES) regardless of the network, which reliably joins
    // WPA2/WPA3-transition APs; deriving it per-device gave a bad wat=5 (SAE) on some phones.
    int[] wifiSec(String ssid) { return new int[]{0, 4}; }

    static String render(String name, String devUuid, String owner, String psk, String mac, boolean cloud) {
        return "=== Home Assistant LocalThings ===\n"
            + "name:          " + name + "\n"
            + "device_id:     " + devUuid + "\n"
            + "owner_id:      " + owner + "\n"
            + "psk (hex):     " + psk + "\n"
            + "ble_mac:       " + mac + "\n"
            + "cloud:         " + (cloud ? "registered" : "local-only") + "\n";
    }

    // ---- persistence ----
    void savePaired(String name, String devUuid, String owner, String psk, String mac, boolean cloud) {
        try {
            SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
            JSONArray arr = new JSONArray(sp.getString(KEY_PAIRED, "[]"));
            JSONObject o = new JSONObject();
            o.put("name", name); o.put("device_id", devUuid); o.put("owner_id", owner);
            o.put("psk", psk); o.put("ble_mac", mac); o.put("cloud", cloud); o.put("ts", System.currentTimeMillis());
            arr.put(o);
            sp.edit().putString(KEY_PAIRED, arr.toString()).apply();
        } catch (Exception e) { log("save err " + e); }
    }

    void showPaired() {
        try {
            JSONArray arr = new JSONArray(getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_PAIRED, "[]"));
            if (arr.length() == 0) { toast("no saved devices yet"); return; }
            String[] labels = new String[arr.length()];
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                labels[i] = o.getString("name") + "\n" + o.getString("device_id") + (o.optBoolean("cloud") ? "  [cloud]" : "");
            }
            new AlertDialog.Builder(this).setTitle("Saved devices").setItems(labels, (d, i) -> {
                try {
                    JSONObject o = arr.getJSONObject(i);
                    java.util.LinkedHashMap<String,String> f = new java.util.LinkedHashMap<>();
                    f.put("ip", ""); f.put("Owner PSK", o.getString("psk"));
                    f.put("name", o.getString("name")); f.put("device_id", o.getString("device_id"));
                    f.put("owner_id", o.getString("owner_id")); f.put("ble_mac", o.optString("ble_mac"));
                    showFieldsDialog(o.getString("name"), f, o.getString("device_id"));
                } catch (Exception e) { log("read err " + e); }
            }).setNeutralButton("Clear all saved", (d,w) -> {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove(KEY_PAIRED).apply(); toast("cleared saved devices");
            }).show();
        } catch (Exception e) { log("paired err " + e); }
    }
}
