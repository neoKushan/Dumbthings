import ssl, socket, threading, time, cbor2, json, sys
from smartthings_local.protocol.coap_tcp import CoapTcpStreamDecoder, build_coap_tcp_message, build_coap_tcp_csm

PORT = 11000
# Point these at your own files. BASE holds the mock cloud's cert/key and log.
# MOCK_HOST is the address the device is told to redirect to (this machine on the LAN).
import os
BASE = os.environ.get("MOCKCLOUD_DIR", "./mockcloud")
CERT = os.path.join(BASE, "server.pem")
MOCK_HOST = os.environ.get("MOCKCLOUD_HOST", "192.0.2.1")  # set to this host's LAN IP
LOG = os.path.join(BASE, "cloud.log")
def L(*a):
    line=f"{time.strftime('%H:%M:%S')} "+" ".join(str(x) for x in a)
    with open(LOG,"a") as f: f.write(line+"\n")
    print(line, flush=True)

def uri_of(m):
    return "/"+"/".join(bytes(o[1]).decode(errors="replace") for o in m.options if o[0]==11)
def mk(code,tok,obj=None):
    return build_coap_tcp_message(code=code,token=tok,options=([(12,bytes([60]))] if obj is not None else []),payload=(cbor2.dumps(obj) if obj is not None else b""))

def handle(conn,addr):
    L("CONN",addr); dec=CoapTcpStreamDecoder()
    try:
        conn.sendall(build_coap_tcp_csm()); conn.settimeout(300)
        while True:
            data=conn.recv(8192)
            if not data: L("EOF",addr); break
            L(f"RECV {len(data)}B from {addr[1]}")
            for m in dec.feed(data):
                u=uri_of(m)
                try: b=cbor2.loads(bytes(m.payload)) if m.payload else None
                except Exception: b=None
                L(f"  MSG 0x{m.code:02x}({m.code>>5}.{m.code&0x1f:02d}) {u} body={json.dumps(b)[:200]}")
                if m.code in (0xE1,0xE3): continue
                if m.code==0xE2: conn.sendall(mk(0xE3,m.token)); L("  ->pong"); continue
                if u.startswith("/oic/account/session"):
                    conn.sendall(mk(68,m.token,{"expiresin":2592000})); L("  ->SIGNIN 2.04")
                elif u.startswith("/oic/account/tokenrefresh"):
                    conn.sendall(mk(68,m.token,{"accesstoken":"mockAT2","refreshtoken":"mockRT","expiresin":2592000})); L("  ->refresh 2.04")
                elif u.startswith("/oic/account/profile"):
                    conn.sendall(mk(68,m.token,{})); L("  ->devprofile 2.04")
                elif u.startswith("/oic/account"):
                    conn.sendall(mk(68,m.token,{"accesstoken":"mockAT","refreshtoken":"mockRT","tokentype":"bearer","expiresin":2592000,"uid":"mock-uid-0001","redirecturi":f"coaps+tcp://{MOCK_HOST}:{PORT}"})); L("  ->SIGNUP 2.04")
                elif u.startswith("/oic/rd"):
                    conn.sendall(mk(68,m.token,b if isinstance(b,dict) else {})); L("  ->RD 2.04")
                elif u.startswith("/oic/ping"):
                    conn.sendall(mk(68,m.token,{})); L("  ->ping-rsc 2.04")
                else:
                    conn.sendall(mk(68,m.token,{})); L(f"  ->default 2.04 {u}")
    except Exception as e: L("ERR",type(e).__name__,str(e)[:120])
    finally:
        try: conn.close()
        except: pass
        L("closed",addr)

def main():
    open(LOG,"w").close()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(BASE,"server.pem"),os.path.join(BASE,"server.key"))
    ctx.verify_mode=ssl.CERT_NONE
    try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception as e: L("cipher warn",e)
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(("0.0.0.0",PORT)); srv.listen(5)
    L(f"STANDALONE mock cloud listening on :{PORT}")
    while True:
        c,a=srv.accept()
        try:
            tc=ctx.wrap_socket(c,server_side=True)
            threading.Thread(target=handle,args=(tc,a),daemon=True).start()
        except Exception as e: L("TLS fail",a,str(e)[:100])

main()
