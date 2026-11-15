package com.poc.stprov;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.util.Log;
import android.webkit.*;
import java.util.*;

/**
 * No-root SmartThings sign-in + token harvest. The web dashboard authenticates by cookie
 * (_JTKN / _SA_TOKEN on .smartthings.com), not a bearer header, so we read the cookie jar
 * natively, test the cookie values as bearers against users/me, and also test whether the raw
 * cookie session authenticates the API. Whichever works becomes our cloud credential.
 */
public class StLoginActivity extends Activity {
    static final String TAG = "STPROV";
    static final String LOGIN_URL = "https://account.smartthings.com/login";

    static final String HOOK =
        "(function(){if(window.__dt)return;window.__dt=1;window.__fc=0;" +
        "function c(t){try{if(t&&t.length>=12)DT.onCandidate(''+t);}catch(e){}}" +
        "function h(x){try{if(x){var m=/Bearer\\s+([A-Za-z0-9._~+/=-]{12,})/i.exec(x);if(m)c(m[1]);}}catch(e){}}" +
        "try{var of=window.fetch;if(of)window.fetch=function(u,i){try{var r=(typeof u=='string')?u:(u&&u.url)||'';" +
        "if(/smartthings\\.com/i.test(r)){window.__fc++;if(i&&i.headers){var H=i.headers;if(H.get)h(H.get('authorization'));" +
        "else{for(var k in H){if(k.toLowerCase()=='authorization')h(H[k]);}}}}}catch(e){}return of.apply(this,arguments);};}catch(e){}" +
        "try{var oo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){this.__u=u;return oo.apply(this,arguments);};" +
        "var os=XMLHttpRequest.prototype.setRequestHeader;XMLHttpRequest.prototype.setRequestHeader=function(k,v){" +
        "try{if(k&&k.toLowerCase()=='authorization'&&/smartthings\\.com/i.test(this.__u||''))h(v);}catch(e){}return os.apply(this,arguments);};}catch(e){}" +
        "function scan(){try{[localStorage,sessionStorage].forEach(function(st){for(var i=0;i<st.length;i++){" +
        "var k=st.key(i),v=st.getItem(k);if(!v)continue;" +
        "try{var o=JSON.parse(v);if(o&&typeof o=='object'){['accessToken','access_token','token','bearer','bearerToken','authToken'].forEach(function(f){if(o[f]&&typeof o[f]=='string')c(o[f]);});}}catch(e){}" +
        "if(/token|bearer|access|auth/i.test(k)&&/^[A-Za-z0-9._~=+-]{16,}$/.test(v))c(v);" +
        "}});}catch(e){}}" +
        "setTimeout(scan,500);setInterval(scan,1500);" +
        "})();";

    final Set<String> tried = Collections.synchronizedSet(new HashSet<String>());
    volatile boolean done;
    WebView wv;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        wv = new WebView(this);
        setContentView(wv);
        WebSettings s = wv.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(wv, true);
        wv.addJavascriptInterface(new Object() {
            @JavascriptInterface public void onCandidate(String t) { consider(t); }
        }, "DT");
        wv.setWebViewClient(new WebViewClient() {
            @Override public void onPageStarted(WebView v, String url, Bitmap f) { v.evaluateJavascript(HOOK, null); }
            @Override public void onPageFinished(WebView v, String url) {
                v.evaluateJavascript(HOOK, null);
                Log.i(TAG, "st-login page: " + url);
                if (url != null && url.contains("smartthings.com")) harvestCookies();
            }
        });
        setTitle("Sign in to SmartThings");
        wv.loadUrl(LOGIN_URL);
    }

    void harvestCookies() {
        String ck = CookieManager.getInstance().getCookie("https://api.smartthings.com");
        if (ck == null) return;
        Log.i(TAG, "st-login cookies(api): " + ck.replaceAll("=[^;]+", "=…"));
        for (String name : new String[]{"_JTKN", "_SA_TOKEN"}) {
            String val = cookieVal(ck, name);
            if (val != null) { Log.i(TAG, "st-login try-cookie " + name + " len=" + val.length()); consider(val); }
        }
        validateCookie(ck);
    }

    static String cookieVal(String cookies, String name) {
        if (cookies == null) return null;
        for (String part : cookies.split(";")) {
            String p = part.trim();
            if (p.startsWith(name + "=")) {
                try { return java.net.URLDecoder.decode(p.substring(name.length() + 1), "UTF-8"); }
                catch (Exception e) { return p.substring(name.length() + 1); }
            }
        }
        return null;
    }

    // Does the raw cookie session authenticate the API directly?
    void validateCookie(final String ck) {
        if (ck == null) return;
        new Thread(() -> {
            try {
                javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection)
                    new java.net.URL("https://auth-global.api.smartthings.com/users/me").openConnection();
                c.setConnectTimeout(10000); c.setReadTimeout(10000);
                c.setRequestProperty("cookie", ck);
                Log.i(TAG, "st-login validate COOKIE -> " + c.getResponseCode());
            } catch (Exception e) { Log.i(TAG, "st-login cookie err " + e); }
        }).start();
    }

    void consider(final String t) {
        if (done || t == null || t.length() < 12 || t.length() > 8192) return;
        if (!tried.add(t)) return;
        Log.i(TAG, "st-login candidate len=" + t.length() + " head=" + t.substring(0, Math.min(5, t.length())));
        new Thread(() -> {
            try {
                javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection)
                    new java.net.URL("https://auth-global.api.smartthings.com/users/me").openConnection();
                c.setConnectTimeout(10000); c.setReadTimeout(10000);
                c.setRequestProperty("authorization", "Bearer " + t);
                int code = c.getResponseCode();
                Log.i(TAG, "st-login validate head=" + t.substring(0, Math.min(5, t.length())) + " -> " + code);
                if (code == 200 && !done) {
                    done = true;
                    runOnUiThread(() -> {
                        Log.i(TAG, "st-login BEARER OK (len=" + t.length() + ")");
                        setResult(RESULT_OK, new Intent().putExtra("bearer", t));
                        finish();
                    });
                }
            } catch (Exception e) { Log.i(TAG, "st-login validate err " + e); }
        }).start();
    }

    @Override public void onBackPressed() {
        if (wv != null && wv.canGoBack()) wv.goBack(); else super.onBackPressed();
    }
}
