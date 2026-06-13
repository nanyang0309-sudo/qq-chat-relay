#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ_chat 中继服务器 v2 (密码认证 + E2E 密钥交换)
纯 Python 内置模块，零依赖。
"""
import json, struct, base64, hashlib, socket, threading, sys, os
from datetime import datetime

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-5AB9DC11B85B"

def we(d):
    d=d if isinstance(d,bytes) else d.encode("utf-8"); f=bytearray([0x81]);L=len(d)
    if L<126: f.append(L)
    elif L<65536: f.extend([126,*struct.pack(">H",L)])
    else: f.extend([127,*struct.pack(">Q",L)])
    f.extend(d); return bytes(f)

def wd(data):
    if len(data)<2: return None,data
    L=data[1]&0x7F; off=2
    if L==126: L=struct.unpack(">H",data[2:4])[0]; off=4
    elif L==127: L=struct.unpack(">Q",data[2:10])[0]; off=10
    if len(data)<off+L: return None,data
    return data[off:off+L],data[off+L:]

def hs(sock):
    try:
        sock.settimeout(5); d=b""
        while b"\r\n\r\n" not in d:
            c=sock.recv(4096)
            if not c: return False
            d+=c
        k=None
        for l in d.decode("utf-8","replace").split("\r\n"):
            if l.lower().startswith("sec-websocket-key:"): k=l.split(":",1)[1].strip(); break
        if not k:
            try:
                hd=d.decode("utf-8","replace")
                if "GET / " in hd or "HEAD / " in hd:
                    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK")
            except:pass
            return False
        ak=base64.b64encode(hashlib.sha1(k.encode()+WS_MAGIC).digest()).decode()
        sock.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ak}\r\n\r\n".encode())
        sock.settimeout(None); return True
    except: return False

class ChatServer:
    def __init__(self):
        self.clients = {}; self.groups = {}; self.pk = {}; self.pw = {}
        self.lock = threading.Lock()

    def log(self, m): print(f"[{datetime.now().strftime('%H:%M:%S')}] {m}", flush=True)
    def snd(self, s, d):
        try: s.sendall(we(json.dumps(d,ensure_ascii=False)))
        except: pass
    def bc(self, d, ex=None):
        for n,s in list(self.clients.items()):
            if n!=ex: self.snd(s,d)

    def handle(self, s, addr):
        buf=b""; nick=None
        try:
            while True:
                c=s.recv(65536)
                if not c: break
                buf+=c
                while True:
                    p,buf=wd(buf)
                    if p is None: break
                    if p==b"__CLOSE__": raise ConnectionResetError()
                    if p==b"__PING__": s.sendall(bytes([0x8A,0x00]))
                    try: m=json.loads(p.decode("utf-8","replace"))
                    except: continue
                    t=m.get("type","")
                    if t=="login":
                        nn=m.get("nickname","").strip()
                        if not nn: self.snd(s,{"type":"error","message":"昵称不能为空"}); continue
                        pw=m.get("password","")
                        pk=m.get("public_key","")
                        with self.lock:
                            if nn in self.pw:
                                h=self.pw[nn]
                                if hashlib.pbkdf2_hmac("sha256",pw.encode(),nn.encode(),100000)!=h:
                                    self.snd(s,{"type":"error","message":"密码错误"}); continue
                            else:
                                self.pw[nn]=hashlib.pbkdf2_hmac("sha256",pw.encode(),nn.encode(),100000)
                            if pk: self.pk[nn]=pk
                            if nn in self.clients:
                                self.snd(s,{"type":"error","message":f"昵称 '{nn}' 已被使用"}); continue
                            self.clients[nn]=s; nick=nn
                        self.log(f"{nick} 上线 (密码认证)")
                        with self.lock:
                            us=list(self.clients.keys())
                            pks={u:self.pk.get(u,"") for u in us}
                            self.bc({"type":"user_joined","nickname":nn,"public_key":pk},ex=nn)
                            self.snd(s,{"type":"login_ok","nickname":nn,"users":us,
                                        "public_keys":pks,
                                        "groups":{g:list(m) for g,m in self.groups.items()}})
                    elif t=="msg_private":
                        to=m.get("to",""); ct=m.get("content",""); en=m.get("encrypted",False)
                        with self.lock:
                            if to in self.clients:
                                self.snd(self.clients[to],{"type":"msg_private","from":nick,"content":ct,"encrypted":en,"timestamp":datetime.now().isoformat()})
                                self.snd(s,{"type":"msg_private_ack","to":to,"content":ct,"encrypted":en,"timestamp":datetime.now().isoformat()})
                            else: self.snd(s,{"type":"error","message":f"用户 '{to}' 不在线"})
                    elif t=="create_group":
                        g=m.get("group","").strip()
                        if not g: self.snd(s,{"type":"error","message":"群名不能为空"}); continue
                        with self.lock:
                            if g in self.groups: self.snd(s,{"type":"error","message":f"群 '{g}' 已存在"}); continue
                            self.groups[g]=[nick]
                        self.log(f"{nick} 创建群 '{g}'")
                        self.bc({"type":"group_created","group":g,"creator":nick})
                        self.snd(s,{"type":"group_joined","group":g,"members":[nick]})
                    elif t=="join_group":
                        g=m.get("group","").strip()
                        if not g: continue
                        with self.lock:
                            if g not in self.groups: self.groups[g]=[]
                            if nick not in self.groups[g]: self.groups[g].append(nick)
                            ms=list(self.groups[g])
                        for n2 in ms:
                            if n2 in self.clients: self.snd(self.clients[n2],{"type":"group_users","group":g,"users":ms})
                    elif t=="msg_group":
                        g=m.get("group",""); ct=m.get("content",""); en=m.get("encrypted",False)
                        with self.lock:
                            if g in self.groups:
                                for n2 in self.groups[g]:
                                    if n2!=nick and n2 in self.clients:
                                        self.snd(self.clients[n2],{"type":"msg_group","from":nick,"group":g,"content":ct,"encrypted":en,"timestamp":datetime.now().isoformat()})
                                self.snd(s,{"type":"msg_group_ack","group":g,"content":ct,"encrypted":en,"timestamp":datetime.now().isoformat()})
                    elif t=="get_public_key":
                        u=m.get("user","")
                        with self.lock:
                            self.snd(s,{"type":"public_key","user":u,"public_key":self.pk.get(u,"")})
        except: pass
        finally:
            if nick:
                with self.lock:
                    self.clients.pop(nick,None)
                    for g in list(self.groups.keys()):
                        if nick in self.groups[g]: self.groups[g].remove(nick)
                    self.bc({"type":"user_left","nickname":nick})
                self.log(f"{nick} 离线")
            try: s.close()
            except: pass

    def start(self, host="0.0.0.0", port=9876):
        if os.environ.get("PORT"): port=int(os.environ["PORT"])
        ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        ss.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        ss.bind((host,port)); ss.listen(100); ss.settimeout(1.0)
        print(f"QQ_chat v2 (密码+E2E) | ws://0.0.0.0:{port}",flush=True)
        while True:
            try:
                cs,addr=ss.accept()
                threading.Thread(target=lambda cs=cs: (hs(cs) and self.handle(cs,addr)) or cs.close(),daemon=True).start()
            except socket.timeout: continue
            except KeyboardInterrupt: break
        ss.close()

if __name__=="__main__":
    port=int(sys.argv[sys.argv.index("--port")+1]) if "--port" in sys.argv else int(os.environ.get("PORT",9876))
    try: ChatServer().start(port=port)
    except KeyboardInterrupt: print("\n已关闭")
