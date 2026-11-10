package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DynamicRunOptions configures container-based `--network none` verification.
type DynamicRunOptions struct {
	DockerImage     string
	RunCmd          string
	Timeout         time.Duration
	DnsAction       string // "sinkhole" (default: A -> 127.0.0.1 for TLS SNI + HTTP capture) or "nxdomain"
	BuildDockerfile bool
}

const airgapObserverSiteCustomizePy = `import json
import os
import socket
import threading

_LOG_PATH = os.environ.get("AIRGAP_CHECK_LOG", "/tmp/airgap_check_attempts.jsonl")
_LOCK = threading.Lock()
_ORIG_GETADDRINFO = socket.getaddrinfo
_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex

def _record(proto, host, port=0, detail=""):
    if not host:
        return
    if isinstance(host, (bytes, bytearray)):
        try:
            h = bytes(host).decode("utf-8", errors="ignore")
        except Exception:
            h = str(host)
    else:
        h = str(host)
    h = h.strip().rstrip(".").lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", ""):
        return
    entry = {"protocol": proto, "host": h, "port": int(port or 0), "detail": str(detail or "")}
    with _LOCK:
        try:
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass

def _hooked_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    p = 0
    try:
        p = int(port)
    except Exception:
        p = 0
    _record("dns_getaddrinfo", host, p, "socket.getaddrinfo")
    return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)

def _hooked_connect(self, address):
    if isinstance(address, tuple) and len(address) >= 2:
        _record("tcp_connect", address[0], address[1], "socket.connect")
    return _ORIG_CONNECT(self, address)

def _hooked_connect_ex(self, address):
    if isinstance(address, tuple) and len(address) >= 2:
        _record("tcp_connect", address[0], address[1], "socket.connect_ex")
    return _ORIG_CONNECT_EX(self, address)

socket.getaddrinfo = _hooked_getaddrinfo
socket.socket.connect = _hooked_connect
socket.socket.connect_ex = _hooked_connect_ex
`

const airgapObserverNodePreloadJS = `const fs = require('fs');
const dns = require('dns');
const net = require('net');

const logPath = process.env.AIRGAP_CHECK_LOG || '/tmp/airgap_check_attempts.jsonl';
function record(proto, host, port, detail) {
  if (!host) return;
  const h = String(host).trim().replace(/\.+$/, '').toLowerCase();
  if (!h || h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return;
  try {
    const fd = fs.openSync(logPath, 'a');
    fs.writeSync(fd, JSON.stringify({ protocol: proto, host: h, port: Number(port || 0), detail: String(detail || '') }) + '\n');
    try { fs.fsyncSync(fd); } catch (_) {}
    fs.closeSync(fd);
  } catch (_) {}
}

const origLookup = dns.lookup;
dns.lookup = function(hostname, options, callback) {
  record('dns_lookup_node', hostname, 0, 'dns.lookup');
  return origLookup.apply(this, arguments);
};

if (dns.promises && typeof dns.promises.lookup === 'function') {
  const origPromiseLookup = dns.promises.lookup.bind(dns.promises);
  dns.promises.lookup = function(hostname, options) {
    record('dns_lookup_node', hostname, 0, 'dns.promises.lookup');
    return origPromiseLookup(hostname, options);
  };
}

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  if (args.length > 0) {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    if (first && typeof first === 'object') {
      const h = first.host || first.servername;
      if (h) {
        record('tcp_connect_node', h, first.port || 0, 'net.Socket.connect');
      }
    } else if (typeof first === 'number' && typeof args[1] === 'string') {
      record('tcp_connect_node', args[1], first, 'net.Socket.connect');
    }
  }
  return origConnect.apply(this, args);
};
`

const airgapLoopbackRunnerPy = `import json
import os
import socket
import subprocess
import sys
import threading
import time

LOG_PATH = "/tmp/airgap_check_attempts.jsonl"
DNS_ACTION = os.environ.get("AIRGAP_DNS_ACTION", "sinkhole").strip().lower()
_WRITE_LOCK = threading.Lock()

def record(proto, host, port=0, detail=""):
    if not host:
        return
    if isinstance(host, (bytes, bytearray)):
        try:
            h = bytes(host).decode("utf-8", errors="ignore")
        except Exception:
            h = str(host)
    else:
        h = str(host)
    h = h.strip().rstrip(".").lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", ""):
        return
    with _WRITE_LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({"protocol": proto, "host": h, "port": int(port or 0), "detail": str(detail or "")}) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass

def _snapshot_proc_pids():
    pids = set()
    try:
        for name in os.listdir("/proc"):
            if name.isdigit():
                pids.add(name)
    except Exception:
        pass
    return pids

def _live_new_pids(baseline):
    live = []
    self_pid = str(os.getpid())
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit() or name == self_pid or name in baseline:
                continue
            try:
                with open("/proc/" + name + "/stat", "r", encoding="utf-8", errors="ignore") as sf:
                    stat_txt = sf.read()
                rparen = stat_txt.rfind(")")
                if rparen >= 0:
                    after = stat_txt[rparen+1:].lstrip()
                    if after and after[0] == "Z":
                        continue
                live.append(name)
            except Exception:
                continue
    except Exception:
        pass
    return live

def parse_dns_question(data):
    pos = 12
    labels = []
    n = len(data)
    while pos < n:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length >= 192:
            pos += 2
            break
        pos += 1
        labels.append(data[pos:pos+length].decode("ascii", errors="ignore"))
        pos += length
    qtype = 0
    qend = pos
    if pos + 4 <= n:
        qtype = int.from_bytes(data[pos:pos+2], "big")
        qend = pos + 4
    return ".".join(labels), qtype, qend

def parse_tls_sni(data):
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
        return ""
    try:
        pos = 43
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return ""
        cs_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(data):
            return ""
        cm_len = data[pos]
        pos += 1 + cm_len
        if pos + 2 > len(data):
            return ""
        exts_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2
        ext_end = min(pos + exts_len, len(data))
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos+2], "big")
            ext_len = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0 and pos + 5 <= len(data):
                name_type = data[pos+2]
                name_len = int.from_bytes(data[pos+3:pos+5], "big")
                if name_type == 0 and pos + 5 + name_len <= len(data):
                    return data[pos+5:pos+5+name_len].decode("utf-8", errors="ignore").lower()
            pos += ext_len
    except Exception:
        return ""
    return ""

def parse_http_request(data):
    try:
        text = data.decode("latin1", errors="ignore")
    except Exception:
        return "", "", ""
    lines = text.split("\r\n")
    if not lines:
        return "", "", ""
    parts = lines[0].split(" ")
    method = parts[0].strip().upper() if len(parts) >= 1 else ""
    raw_target = parts[1].strip() if len(parts) >= 2 else "/"
    host = ""
    if "://" in raw_target:
        after_scheme = raw_target.split("://", 1)[1]
        host_part = after_scheme.split("/", 1)[0]
        host = host_part.split(":", 1)[0].strip().lower()
        path = "/" + after_scheme.split("/", 1)[1] if "/" in after_scheme else "/"
    elif method == "CONNECT":
        host = raw_target.split(":", 1)[0].strip().lower()
        path = ""
    else:
        path = raw_target
    path_no_query = path.split("?", 1)[0]
    if not host:
        for hdr in lines[1:]:
            if hdr == "":
                break
            if ":" in hdr:
                k, v = hdr.split(":", 1)
                if k.strip().lower() == "host":
                    host = v.strip().split(":", 1)[0].lower()
                    break
    return method, host, path_no_query

def start_dns_sinkhole():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 53))
    except Exception:
        return False
    def loop():
        while True:
            try:
                data, addr = s.recvfrom(1024)
                if len(data) < 12:
                    continue
                qname, qtype, qend = parse_dns_question(data)
                if qname:
                    detail = "UDP:53 DNS sinkhole -> 127.0.0.1" if DNS_ACTION != "nxdomain" else "UDP:53 DNS query -> NXDOMAIN"
                    record("dns_udp53", qname, 53, detail)
                question = data[12:qend] if qend <= len(data) else data[12:]
                if DNS_ACTION == "nxdomain":
                    resp = data[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question
                elif qtype == 1:
                    ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x7f\x00\x00\x01"
                    resp = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + ans
                else:
                    resp = data[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + question
                s.sendto(resp, addr)
            except Exception:
                break
    threading.Thread(target=loop, daemon=True).start()
    try:
        with open("/etc/resolv.conf", "w", encoding="utf-8") as rf:
            rf.write("nameserver 127.0.0.1\noptions ndots:0 timeout:1 attempts:1\n")
        return True
    except Exception:
        return False

def start_tls_sinkhole(port=443):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(64)
    except Exception:
        return False
    def handle(conn):
        try:
            conn.settimeout(1.5)
            data = conn.recv(4096)
            sni = parse_tls_sni(data)
            if sni:
                record("tls_sni", sni, port, "TLS ClientHello SNI captured on loopback:443")
            conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except Exception:
                break
    threading.Thread(target=accept_loop, daemon=True).start()
    return True

def start_http_sinkhole(port=80):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(64)
    except Exception:
        return 0
    actual_port = srv.getsockname()[1]
    def handle(conn):
        try:
            conn.settimeout(1.5)
            data = conn.recv(4096)
            method, host, clean_path = parse_http_request(data)
            if host:
                if method == "CONNECT":
                    record("http_proxy_connect", host, actual_port, "CONNECT tunnel intercepted via HTTP_PROXY")
                else:
                    proto = "http_proxy_connect" if port == 0 else "http_egress"
                    record(proto, host, actual_port, (method + " " + clean_path).strip())
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except Exception:
                break
    threading.Thread(target=accept_loop, daemon=True).start()
    return actual_port

if __name__ == "__main__":
    open(LOG_PATH, "w").close()
    dns_ok = start_dns_sinkhole()
    tls_ok = start_tls_sinkhole(443)
    http_ok = start_http_sinkhole(80) > 0
    proxy_port = 0
    if not (dns_ok and tls_ok and http_ok):
        proxy_port = start_http_sinkhole(0)

    cmd = sys.argv[1:]
    env = os.environ.copy()
    env["AIRGAP_CHECK_LOG"] = LOG_PATH
    hook_dir = "/tmp/airgap_hook"
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = hook_dir + (":" + existing_pp if existing_pp else "")
    existing_no = env.get("NODE_OPTIONS", "")
    node_req = "--require " + hook_dir + "/node_preload.js"
    env["NODE_OPTIONS"] = (existing_no + " " + node_req).strip()
    if proxy_port > 0:
        purl = "http://127.0.0.1:" + str(proxy_port)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env.setdefault(k, purl)

    baseline_pids = _snapshot_proc_pids()
    proc = subprocess.run(cmd, env=env)
    saw_new = False
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _live_new_pids(baseline_pids):
            break
        saw_new = True
        time.sleep(0.025)
    if saw_new:
        time.sleep(0.03)
    print("===AIRGAP_CHECK_LOG_BEGIN===", file=sys.stderr)
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            sys.stderr.write(f.read())
    except Exception:
        pass
    print("===AIRGAP_CHECK_LOG_END===", file=sys.stderr)
    sys.exit(proc.returncode)
`

const airgapLoopbackRunnerJS = `const dgram = require('dgram');
const fs = require('fs');
const net = require('net');
const { spawn } = require('child_process');

const LOG_PATH = '/tmp/airgap_check_attempts.jsonl';
const DNS_ACTION = (process.env.AIRGAP_DNS_ACTION || 'sinkhole').trim().toLowerCase();

function record(proto, host, port, detail) {
  if (!host) return;
  const h = String(host).trim().replace(/\.+$/, '').toLowerCase();
  if (!h || h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return;
  try {
    const fd = fs.openSync(LOG_PATH, 'a');
    fs.writeSync(fd, JSON.stringify({ protocol: proto, host: h, port: Number(port || 0), detail: String(detail || '') }) + '\n');
    try { fs.fsyncSync(fd); } catch (_) {}
    fs.closeSync(fd);
  } catch (_) {}
}

function snapshotProcPids() {
  const pids = new Set();
  try {
    for (const name of fs.readdirSync('/proc')) {
      if (/^\d+$/.test(name)) pids.add(name);
    }
  } catch (_) {}
  return pids;
}

function liveNewPids(baseline) {
  const live = [];
  const selfPid = String(process.pid);
  try {
    for (const name of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(name) || name === selfPid || baseline.has(name)) continue;
      try {
        const statTxt = fs.readFileSync('/proc/' + name + '/stat', 'utf8');
        const rparen = statTxt.lastIndexOf(')');
        if (rparen >= 0) {
          const after = statTxt.slice(rparen + 1).trimStart();
          if (after.startsWith('Z')) continue;
        }
        live.push(name);
      } catch (_) {}
    }
  } catch (_) {}
  return live;
}

function parseDnsQuestion(buf) {
  let pos = 12;
  const labels = [];
  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      break;
    }
    if (len >= 192) {
      pos += 2;
      break;
    }
    pos += 1;
    labels.push(buf.slice(pos, pos + len).toString('ascii'));
    pos += len;
  }
  let qtype = 0;
  let qend = pos;
  if (pos + 4 <= buf.length) {
    qtype = buf.readUInt16BE(pos);
    qend = pos + 4;
  }
  return { qname: labels.join('.'), qtype, qend };
}

function parseTlsSni(buf) {
  if (!buf || buf.length < 44 || buf[0] !== 0x16 || buf[5] !== 0x01) return '';
  try {
    let pos = 43;
    const sidLen = buf[pos];
    pos += 1 + sidLen;
    if (pos + 2 > buf.length) return '';
    const csLen = buf.readUInt16BE(pos);
    pos += 2 + csLen;
    if (pos + 1 > buf.length) return '';
    const cmLen = buf[pos];
    pos += 1 + cmLen;
    if (pos + 2 > buf.length) return '';
    const extsLen = buf.readUInt16BE(pos);
    pos += 2;
    const extEnd = Math.min(pos + extsLen, buf.length);
    while (pos + 4 <= extEnd) {
      const extType = buf.readUInt16BE(pos);
      const extLen = buf.readUInt16BE(pos + 2);
      pos += 4;
      if (extType === 0 && pos + 5 <= buf.length) {
        const nameType = buf[pos + 2];
        const nameLen = buf.readUInt16BE(pos + 3);
        if (nameType === 0 && pos + 5 + nameLen <= buf.length) {
          return buf.slice(pos + 5, pos + 5 + nameLen).toString('utf8').toLowerCase();
        }
      }
      pos += extLen;
    }
  } catch (_) {}
  return '';
}

function parseHttpRequest(buf) {
  const text = buf.toString('latin1');
  const lines = text.split('\r\n');
  if (!lines.length) return { method: '', host: '', cleanPath: '' };
  const parts = lines[0].split(' ');
  const method = (parts[0] || '').trim().toUpperCase();
  const rawTarget = (parts[1] || '/').trim();
  let host = '';
  let path = rawTarget;
  if (rawTarget.includes('://')) {
    const afterScheme = rawTarget.split('://', 2)[1];
    const slashIdx = afterScheme.indexOf('/');
    const hostPort = slashIdx >= 0 ? afterScheme.slice(0, slashIdx) : afterScheme;
    host = hostPort.split(':', 1)[0].trim().toLowerCase();
    path = slashIdx >= 0 ? afterScheme.slice(slashIdx) : '/';
  } else if (method === 'CONNECT') {
    host = rawTarget.split(':', 1)[0].trim().toLowerCase();
    path = '';
  }
  const cleanPath = path.split('?', 1)[0];
  if (!host) {
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') break;
      const col = lines[i].indexOf(':');
      if (col > 0 && lines[i].slice(0, col).trim().toLowerCase() === 'host') {
        host = lines[i].slice(col + 1).trim().split(':', 1)[0].toLowerCase();
        break;
      }
    }
  }
  return { method, host, cleanPath };
}

function startDnsSinkhole() {
  return new Promise((resolve) => {
    try {
      const sock = dgram.createSocket('udp4');
      sock.on('error', () => resolve(false));
      sock.on('message', (msg, rinfo) => {
        if (msg.length < 12) return;
        const { qname, qtype, qend } = parseDnsQuestion(msg);
        if (qname) {
          record('dns_udp53', qname, 53, DNS_ACTION === 'nxdomain' ? 'UDP:53 DNS query -> NXDOMAIN' : 'UDP:53 DNS sinkhole -> 127.0.0.1');
        }
        const question = msg.slice(12, qend <= msg.length ? qend : msg.length);
        let resp;
        if (DNS_ACTION === 'nxdomain') {
          resp = Buffer.concat([msg.slice(0, 2), Buffer.from([0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), question]);
        } else if (qtype === 1) {
          const ans = Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 127, 0, 0, 1]);
          resp = Buffer.concat([msg.slice(0, 2), Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]), question, ans]);
        } else {
          resp = Buffer.concat([msg.slice(0, 2), Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), question]);
        }
        sock.send(resp, rinfo.port, rinfo.address, () => {});
      });
      sock.bind(53, '127.0.0.1', () => {
        sock.unref();
        try {
          fs.writeFileSync('/etc/resolv.conf', 'nameserver 127.0.0.1\noptions ndots:0 timeout:1 attempts:1\n');
          resolve(true);
        } catch (_) {
          resolve(false);
        }
      });
    } catch (_) {
      resolve(false);
    }
  });
}

function startTlsSinkhole(port) {
  return new Promise((resolve) => {
    try {
      const srv = net.createServer((conn) => {
        conn.setTimeout(1500, () => conn.destroy());
        conn.once('data', (chunk) => {
          const sni = parseTlsSni(chunk);
          if (sni) record('tls_sni', sni, port, 'TLS ClientHello SNI captured on loopback:443');
          try {
            conn.end(Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
          } catch (_) {
            conn.destroy();
          }
        });
        conn.on('error', () => {});
      });
      srv.on('error', () => resolve(false));
      srv.listen(port, '127.0.0.1', () => {
        srv.unref();
        resolve(true);
      });
    } catch (_) {
      resolve(false);
    }
  });
}

function startHttpSinkhole(port) {
  return new Promise((resolve) => {
    try {
      const srv = net.createServer((conn) => {
        const boundPort = srv.address() ? srv.address().port : port;
        conn.setTimeout(1500, () => conn.destroy());
        conn.once('data', (chunk) => {
          const { method, host, cleanPath } = parseHttpRequest(chunk);
          if (host) {
            if (method === 'CONNECT') {
              record('http_proxy_connect', host, boundPort, 'CONNECT tunnel intercepted via HTTP_PROXY');
            } else {
              const proto = port === 0 ? 'http_proxy_connect' : 'http_egress';
              record(proto, host, boundPort, (method + ' ' + cleanPath).trim());
            }
          }
          try {
            conn.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
          } catch (_) {
            conn.destroy();
          }
        });
        conn.on('error', () => {});
      });
      srv.on('error', () => resolve(0));
      srv.listen(port, '127.0.0.1', () => {
        srv.unref();
        resolve(srv.address() ? srv.address().port : port);
      });
    } catch (_) {
      resolve(0);
    }
  });
}

(async () => {
  fs.writeFileSync(LOG_PATH, '');
  const dnsOk = await startDnsSinkhole();
  const tlsOk = await startTlsSinkhole(443);
  const httpPort = await startHttpSinkhole(80);
  let proxyPort = 0;
  if (!dnsOk || !tlsOk || httpPort <= 0) {
    proxyPort = await startHttpSinkhole(0);
  }

  const hookDir = '/tmp/airgap_hook';
  const env = Object.assign({}, process.env, {
    AIRGAP_CHECK_LOG: LOG_PATH,
    PYTHONPATH: hookDir + (process.env.PYTHONPATH ? ':' + process.env.PYTHONPATH : ''),
    NODE_OPTIONS: ((process.env.NODE_OPTIONS || '') + ' --require ' + hookDir + '/node_preload.js').trim(),
  });
  if (proxyPort > 0) {
    const purl = 'http://127.0.0.1:' + proxyPort;
    env.HTTP_PROXY = env.HTTP_PROXY || purl;
    env.HTTPS_PROXY = env.HTTPS_PROXY || purl;
    env.http_proxy = env.http_proxy || purl;
    env.https_proxy = env.https_proxy || purl;
  }

  const baselinePids = snapshotProcPids();
  const args = process.argv.slice(2);
  const child = spawn(args[0], args.slice(1), { env, stdio: 'inherit' });
  const exitCode = await new Promise((resolve) => {
    child.on('error', () => resolve(1));
    child.on('close', (code) => resolve(code == null ? 1 : code));
  });
  let sawNew = false;
  const deadline = Date.now() + 1000;
  while (Date.now() < deadline) {
    if (liveNewPids(baselinePids).length === 0) break;
    sawNew = true;
    await new Promise((r) => setTimeout(r, 25));
  }
  if (sawNew) {
    await new Promise((r) => setTimeout(r, 30));
  }
  process.stderr.write('\n===AIRGAP_CHECK_LOG_BEGIN===\n');
  try {
    process.stderr.write(fs.readFileSync(LOG_PATH, 'utf8'));
  } catch (_) {}
  process.stderr.write('===AIRGAP_CHECK_LOG_END===\n');
  process.exit(exitCode);
})();
`

func RunDynamicAirgapCheck(ctx context.Context, absPath string, report *CheckReport, opts DynamicRunOptions) (*DynamicCheckResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 45 * time.Second
	}
	dnsAction := strings.ToLower(strings.TrimSpace(opts.DnsAction))
	if dnsAction == "" {
		dnsAction = "sinkhole"
	}
	if dnsAction != "sinkhole" && dnsAction != "nxdomain" {
		return nil, fmt.Errorf("invalid --dns-action %q (must be 'sinkhole' or 'nxdomain')", opts.DnsAction)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker CLI is required for --run dynamic air-gap verification: %w", err)
	}

	image := strings.TrimSpace(opts.DockerImage)
	autoBuilt := false
	if image == "" && opts.BuildDockerfile {
		dockerfilePath := filepath.Join(absPath, "Dockerfile")
		if _, err := os.Stat(dockerfilePath); err != nil {
			return nil, fmt.Errorf("--build requested, but no Dockerfile found at %s", dockerfilePath)
		}
		tmpTag := fmt.Sprintf("airgap-check-tmp:%d", time.Now().UnixNano())
		buildTimeout := opts.Timeout
		if buildTimeout < 180*time.Second {
			buildTimeout = 180 * time.Second
		}
		buildCtx, cancelBuild := context.WithTimeout(ctx, buildTimeout)
		defer cancelBuild()
		buildCmd := exec.CommandContext(buildCtx, "docker", "build", "-t", tmpTag, "-f", dockerfilePath, absPath)
		if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
			return nil, fmt.Errorf("building Dockerfile with `docker build` failed: %v\n%s", bErr, truncateLines(string(out), 15))
		}
		image = tmpTag
		autoBuilt = true
		defer func() {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cleanCancel()
			_ = exec.CommandContext(cleanCtx, "docker", "rmi", "-f", tmpTag).Run()
		}()
	}

	if image == "" {
		image = selectDefaultDynamicImage(absPath)
	}

	userCmd := strings.TrimSpace(opts.RunCmd)
	if userCmd == "" {
		userCmd = synthesizeDynamicProbeCommand(absPath)
	}

	hookHostDir, err := os.MkdirTemp("", "airgap-check-hook-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp hook dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(hookHostDir) }()
	_ = os.Chmod(hookHostDir, 0o755)

	attemptsFile, err := os.CreateTemp("", "airgap-check-attempts-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("creating temp attempts file: %w", err)
	}
	attemptsHostPath := attemptsFile.Name()
	_ = attemptsFile.Close()
	_ = os.Chmod(attemptsHostPath, 0o666)
	defer func() { _ = os.Remove(attemptsHostPath) }()

	if err := os.WriteFile(filepath.Join(hookHostDir, "sitecustomize.py"), []byte(airgapObserverSiteCustomizePy), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hookHostDir, "node_preload.js"), []byte(airgapObserverNodePreloadJS), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hookHostDir, "runner.py"), []byte(airgapLoopbackRunnerPy), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hookHostDir, "runner.js"), []byte(airgapLoopbackRunnerJS), 0o644); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	quotedCmd := shellSingleQuote(userCmd)
	// Choose Python observer first, else pure Node.js observer, else raw shell execution.
	// IMPORTANT: Never set NODE_OPTIONS or PYTHONPATH in outer `docker run -e` so runner.js does not double-hook itself.
	shellWrapper := fmt.Sprintf(
		`: > /tmp/airgap_check_attempts.jsonl; if command -v python3 >/dev/null 2>&1; then echo "===AIRGAP_OBSERVER_RUNTIME:python3+udp53+sni===" >&2; python3 /tmp/airgap_hook/runner.py sh -c %s; elif command -v node >/dev/null 2>&1; then echo "===AIRGAP_OBSERVER_RUNTIME:node+udp53+sni===" >&2; node /tmp/airgap_hook/runner.js sh -c %s; else echo "===AIRGAP_OBSERVER_RUNTIME:shell_only===" >&2; (%s); rc=$?; echo "===AIRGAP_CHECK_LOG_BEGIN===" >&2; cat /tmp/airgap_check_attempts.jsonl >&2 2>/dev/null; echo "===AIRGAP_CHECK_LOG_END===" >&2; exit $rc; fi`,
		quotedCmd, quotedCmd, userCmd,
	)

	containerName := fmt.Sprintf("airgap-check-%d", time.Now().UnixNano())
	dockerArgs := []string{
		"run", "--rm",
		"--name", containerName,
		"--entrypoint", "",
		"--network", "none",
		"-e", "AIRGAP_CHECK_LOG=/tmp/airgap_check_attempts.jsonl",
		"-e", "AIRGAP_DNS_ACTION=" + dnsAction,
		"-v", fmt.Sprintf("%s:/workspace:ro", absPath),
		"-v", fmt.Sprintf("%s:/tmp/airgap_hook:ro", hookHostDir),
		"-v", fmt.Sprintf("%s:/tmp/airgap_check_attempts.jsonl:rw", attemptsHostPath),
		"-w", "/workspace",
		image,
		"sh", "-c",
		shellWrapper,
	}

	start := time.Now()
	cmd := exec.CommandContext(runCtx, "docker", dockerArgs...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	durationMs := time.Since(start).Milliseconds()
	timedOut := runCtx.Err() == context.DeadlineExceeded
	if runCtx.Err() != nil {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", containerName).Run()
		cleanCancel()
	}

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	rawStderr := stderrBuf.String()
	observerRuntime, strippedStderr := extractObserverRuntime(rawStderr)
	attempts, cleanStderr := extractDynamicAttempts(strippedStderr, stdoutBuf.String(), attemptsHostPath)
	failureCat := classifyDynamicFailureWithTimeout(exitCode, cleanStderr, attempts, timedOut)

	return &DynamicCheckResult{
		Executed:         true,
		DockerImage:      image,
		AutoBuiltImage:   autoBuilt,
		Command:          userCmd,
		NetworkMode:      "none (kernel-isolated --network none)",
		ObserverRuntime:  observerRuntime,
		ExitCode:         exitCode,
		DurationMs:       durationMs,
		CrashedInAirgap:  exitCode != 0 || failureCat != "",
		FailureCategory:  failureCat,
		ObservedAttempts: attempts,
		StderrSnippet:    truncateLines(cleanStderr, 12),
	}, nil
}

func selectDefaultDynamicImage(absPath string) string {
	for _, f := range []string{"requirements.txt", "pyproject.toml", "Pipfile", "backend/requirements.txt"} {
		if _, err := os.Stat(filepath.Join(absPath, f)); err == nil {
			return "python:3.12-slim-bookworm"
		}
	}
	if _, err := os.Stat(filepath.Join(absPath, "package.json")); err == nil {
		return "node:20-bookworm-slim"
	}
	return "python:3.12-slim-bookworm"
}

func synthesizeDynamicProbeCommand(absPath string) string {
	for _, entry := range []string{"app.py", "main.py", "server.py", "backend/server.py", "backend/main.py"} {
		if _, err := os.Stat(filepath.Join(absPath, entry)); err == nil {
			return "python3 " + entry
		}
	}
	if pkgRaw, err := os.ReadFile(filepath.Join(absPath, "package.json")); err == nil {
		var pkg struct {
			Main    string            `json:"main"`
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(pkgRaw, &pkg) == nil {
			if pkg.Main != "" {
				if _, sErr := os.Stat(filepath.Join(absPath, pkg.Main)); sErr == nil {
					return "node " + pkg.Main
				}
			}
		}
	}
	for _, entry := range []string{"server.js", "app.js", "index.js", "src/index.js", "dist/index.js"} {
		if _, err := os.Stat(filepath.Join(absPath, entry)); err == nil {
			return "node " + entry
		}
	}
	return "python3 -c 'print(\"airgap-probe\")'"
}

func extractObserverRuntime(rawStderr string) (string, string) {
	const prefix = "===AIRGAP_OBSERVER_RUNTIME:"
	const suffix = "==="
	idx := strings.Index(rawStderr, prefix)
	if idx < 0 {
		return "unknown", rawStderr
	}
	rest := rawStderr[idx+len(prefix):]
	end := strings.Index(rest, suffix)
	if end < 0 {
		return "unknown", rawStderr
	}
	rt := strings.TrimSpace(rest[:end])
	before := rawStderr[:idx]
	after := strings.TrimLeft(rest[end+len(suffix):], "\r\n")
	return rt, before + after
}

func stripURLQuery(rawURL string) string {
	if idx := strings.IndexByte(rawURL, '?'); idx >= 0 {
		return rawURL[:idx]
	}
	return rawURL
}

var (
	enotfoundWordRe   = regexp.MustCompile(`(?i)\benotfound\b`)
	gaierrorWordRe    = regexp.MustCompile(`(?i)\bgaierror\b`)
	urlErrorContextRe = regexp.MustCompile(`(?i)\b(?:urlerror|httperror|connectionerror|connecterror|maxretryerror|clientconnectorerror|requestexception|urlopen error|getaddrinfo|econnrefused|enotfound|enetunreach|handshake failure|certificate verify failed|fetching|downloading|failed to (?:fetch|download|connect)|could not (?:resolve|connect|download|fetch))\b`)
	docInviteLineRe   = regexp.MustCompile(`(?i)(?:for further information|for more details|see https?://|read the docs|documentation|migrate to)`)
)

func normalizeAttemptHost(raw string) string {
	h := strings.TrimSpace(raw)
	if len(h) >= 3 && (h[0] == 'b' || h[0] == 'B') &&
		((h[1] == '\'' && h[len(h)-1] == '\'') || (h[1] == '"' && h[len(h)-1] == '"')) {
		h = h[2 : len(h)-1]
	}
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(strings.TrimSpace(h))
}

func isLoopbackOrWildcardHost(h string) bool {
	switch h {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return false
}

func isIgnoredRuntimeErrorHost(host string) bool {
	if isIgnoredLocalOrDocHost(host) || isLoopbackOrWildcardHost(host) {
		return true
	}
	switch host {
	case "errors.pydantic.dev", "cloud.google.com", "sharp.pixelplumbing.com",
		"pptr.dev", "playwright.dev", "developer.chrome.com", "docs.python.org", "docs.npmjs.com":
		return true
	}
	return strings.HasPrefix(host, "docs.") || strings.HasPrefix(host, "errors.")
}

func extractDynamicAttemptsFromStderr(rawStderr, rawStdout string) ([]DynamicEgressAttempt, string) {
	return extractDynamicAttempts(rawStderr, rawStdout, "")
}

func extractDynamicAttempts(rawStderr, rawStdout, attemptsHostPath string) ([]DynamicEgressAttempt, string) {
	const beginMarker = "===AIRGAP_CHECK_LOG_BEGIN==="
	const endMarker = "===AIRGAP_CHECK_LOG_END==="

	attempts := []DynamicEgressAttempt{}
	seen := make(map[string]bool)

	ingestJSONL := func(rawBlock string) {
		for _, line := range strings.Split(rawBlock, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var att DynamicEgressAttempt
			if err := json.Unmarshal([]byte(line), &att); err == nil {
				att.Host = normalizeAttemptHost(att.Host)
				if isLoopbackOrWildcardHost(att.Host) {
					continue
				}
				if att.Protocol == "http_egress" {
					att.Detail = stripURLQuery(att.Detail)
				}
				key := fmt.Sprintf("%s|%s|%d", att.Protocol, att.Host, att.Port)
				if att.Protocol == "http_egress" {
					key += "|" + att.Detail
				}
				if !seen[key] {
					seen[key] = true
					attempts = append(attempts, att)
				}
			}
		}
	}

	if attemptsHostPath != "" {
		if fileBytes, err := os.ReadFile(attemptsHostPath); err == nil && len(fileBytes) > 0 {
			ingestJSONL(string(fileBytes))
		}
	}

	cleanStderr := rawStderr
	if idxBegin := strings.Index(rawStderr, beginMarker); idxBegin >= 0 {
		after := rawStderr[idxBegin+len(beginMarker):]
		if idxEnd := strings.Index(after, endMarker); idxEnd >= 0 {
			logBlock := after[:idxEnd]
			cleanStderr = strings.TrimSpace(rawStderr[:idxBegin] + after[idxEnd+len(endMarker):])
			ingestJSONL(logBlock)
		}
	}

	combined := cleanStderr + "\n" + rawStdout
	for _, line := range strings.Split(combined, "\n") {
		if !strings.Contains(line, "http://") && !strings.Contains(line, "https://") {
			continue
		}
		if docInviteLineRe.MatchString(line) || !urlErrorContextRe.MatchString(line) {
			continue
		}
		for _, m := range httpsURLRegex.FindAllStringSubmatch(line, -1) {
			if len(m) >= 2 {
				host := normalizeAttemptHost(m[1])
				if host != "" && !isIgnoredRuntimeErrorHost(host) {
					key := "runtime_error_url|" + host + "|443"
					if !seen[key] {
						seen[key] = true
						attempts = append(attempts, DynamicEgressAttempt{
							Protocol: "runtime_error_url",
							Host:     host,
							Port:     443,
							Detail:   stripURLQuery(m[0]),
						})
					}
				}
			}
		}
	}

	return attempts, cleanStderr
}

func classifyDynamicFailure(exitCode int, stderr string, attempts []DynamicEgressAttempt) string {
	return classifyDynamicFailureWithTimeout(exitCode, stderr, attempts, false)
}

func classifyDynamicFailureWithTimeout(exitCode int, stderr string, attempts []DynamicEgressAttempt, timedOut bool) string {
	if timedOut {
		return "TIMEOUT_EXCEEDED_IN_AIRGAP"
	}
	if exitCode == 0 {
		if len(attempts) > 0 {
			return "SILENT_EGRESS_ATTEMPTED_AND_DROPPED"
		}
		return ""
	}
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "temporary failure in name resolution") ||
		gaierrorWordRe.MatchString(stderr) ||
		strings.Contains(lower, "name or service not known") ||
		enotfoundWordRe.MatchString(stderr):
		return "DNS_RESOLUTION_BLOCKED_IN_AIRGAP"
	case strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "connectionerror") ||
		strings.Contains(lower, "connecterror") ||
		strings.Contains(lower, "maxretryerror") ||
		strings.Contains(lower, "econnrefused") ||
		strings.Contains(lower, "ssl") && strings.Contains(lower, "handshake failure") ||
		strings.Contains(lower, "enetunreach"):
		return "NETWORK_EGRESS_BLOCKED_IN_AIRGAP"
	case strings.Contains(lower, "executable doesn't exist") ||
		strings.Contains(lower, "can't load") ||
		strings.Contains(lower, "local_files_only") ||
		strings.Contains(lower, "cannotloadmodel") ||
		(strings.Contains(lower, "resource ") && strings.Contains(lower, "not found")):
		return "MISSING_OFFLINE_ASSET_OR_WEIGHTS"
	case strings.Contains(lower, "read-only file system") ||
		strings.Contains(lower, "permission denied: '/root/.cache"):
		return "READONLY_ROOTFS_CACHE_WRITE_FAILURE"
	case strings.Contains(lower, "modulenotfounderror") ||
		strings.Contains(lower, "no module named ") ||
		strings.Contains(lower, "cannot find module") ||
		strings.Contains(lower, "err_module_not_found"):
		return "DEPENDENCY_NOT_INSTALLED_IN_BASE_IMAGE (pass --image <built-app-image> or --build)"
	default:
		return "NON_ZERO_EXIT_IN_AIRGAP"
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncateLines(s string, maxLines int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[len(lines)-maxLines:], "\n")
}
