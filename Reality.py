#!/usr/bin/env python3
import argparse
import asyncio
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.request

# ================= НАСТРОЙКИ СКОРОСТИ =================
CONNECT_TIMEOUT = 0.5  # Оптимально для быстрого пропуска мёртвых IP
MAX_HOSTS_PER_24 = 254
MAX_SAMPLED_24_PER_LARGE_PREFIX = 4

BANNED_TLDS = {
    "crl", "ocsp", "der", "crt", "cer", "pem", "arpa", 
    "local", "internal", "invalid", "example", "test", "localhost"
}

# SSL Контексты
CTX_RAW = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX_RAW.check_hostname = False
CTX_RAW.verify_mode = ssl.CERT_NONE

CTX_REALITY = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX_REALITY.check_hostname = False
CTX_REALITY.verify_mode = ssl.CERT_NONE
CTX_REALITY.set_alpn_protocols(["h2", "http/1.1"])
CTX_REALITY.minimum_version = ssl.TLSVersion.TLSv1_3
CTX_REALITY.maximum_version = ssl.TLSVersion.TLSv1_3

DNS_CACHE = {}

# ================= HPACK / H2 ENGINE (RFC 7540 / RFC 7541) =================

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

STATIC_TABLE = [
    ("", ""), (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"),
    (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"),
    (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""),
    ("host", ""), ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""),
    ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""),
    ("retry-after", ""), ("server", ""), ("set-cookie", ""),
    ("strict-transport-security", ""), ("transfer-encoding", ""), ("user-agent", ""),
    ("vary", ""), ("via", ""), ("www-authenticate", "")
]

HUFFMAN_TABLE = (
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12), (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8), (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23), (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21), (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
)

HUFFMAN_TREE = {}
for sym, (code, bits) in enumerate(HUFFMAN_TABLE):
    curr = HUFFMAN_TREE
    for b in range(bits - 1, -1, -1):
        bit = (code >> b) & 1
        if bit not in curr:
            curr[bit] = {}
        curr = curr[bit]
    curr["sym"] = sym

def decode_huffman(raw_bytes):
    out = bytearray()
    node = HUFFMAN_TREE
    for byte in raw_bytes:
        for b in range(7, -1, -1):
            bit = (byte >> b) & 1
            node = node.get(bit, HUFFMAN_TREE)
            if "sym" in node:
                sym = node["sym"]
                if sym == 256:
                    return out.decode("latin1", errors="ignore")
                out.append(sym)
                node = HUFFMAN_TREE
    return out.decode("latin1", errors="ignore")

def decode_hpack_int(data, offset, prefix_bits):
    max_prefix = (1 << prefix_bits) - 1
    if offset >= len(data): return 0, offset
    val = data[offset] & max_prefix
    offset += 1
    if val < max_prefix: return val, offset
    m = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        val += (b & 0x7F) << m
        m += 7
        if not (b & 0x80): break
    return val, offset

def decode_hpack_string(data, offset):
    if offset >= len(data): return "", offset
    huffman = bool(data[offset] & 0x80)
    str_len, offset = decode_hpack_int(data, offset, 7)
    if offset + str_len > len(data): return "", offset
    raw_bytes = data[offset : offset + str_len]
    offset += str_len
    if huffman:
        return decode_huffman(raw_bytes), offset
    return raw_bytes.decode("latin1", errors="ignore"), offset

def parse_hpack_headers(payload, flags=0):
    headers = {}
    try:
        offset = 0
        pad_len = payload[offset] if (flags & 0x08) and offset < len(payload) else 0
        offset += 1 if (flags & 0x08) else 0
        offset += 5 if (flags & 0x20) else 0
        end_offset = len(payload) - pad_len if len(payload) >= pad_len else len(payload)

        while offset < end_offset:
            b = payload[offset]
            if b & 0x80:
                index, offset = decode_hpack_int(payload, offset, 7)
                if 1 <= index < len(STATIC_TABLE):
                    k, v = STATIC_TABLE[index]
                    headers[k.lower()] = v
            elif (b & 0xC0) == 0x40 or (b & 0xF0) == 0x00 or (b & 0xF0) == 0x10:
                prefix = 6 if (b & 0xC0) == 0x40 else 4
                index, offset = decode_hpack_int(payload, offset, prefix)
                if index == 0:
                    k, offset = decode_hpack_string(payload, offset)
                elif 1 <= index < len(STATIC_TABLE):
                    k = STATIC_TABLE[index][0]
                else:
                    k = "unknown"
                v, offset = decode_hpack_string(payload, offset)
                headers[k.lower()] = v
            elif (b & 0xE0) == 0x20:
                _, offset = decode_hpack_int(payload, offset, 5)
            else:
                offset += 1
    except Exception:
        pass
    return headers

def build_h2_frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = length.to_bytes(3, "big") + bytes([frame_type, flags]) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return header + payload

def build_h2_request_headers(sni):
    payload = bytearray([0x82, 0x87, 0x84])  # GET, https, /
    sni_bytes = sni.encode("ascii")
    payload.extend([0x01, len(sni_bytes)])
    payload.extend(sni_bytes)
    ua = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    payload.extend([0x0F, 0x2B, len(ua)])
    payload.extend(ua)
    return bytes(payload)


# ================= BGP & Geo Helpers =================

def fetch_ripestat_safe(endpoint, resource, params="", timeout=8):
    try:
        url = f"https://stat.ripe.net/data/{endpoint}/data.json?resource={resource}{params}"
        req = urllib.request.Request(url, headers={"User-Agent": "RIPE-Reality-Scanner/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            return data.get("data", {})
    except Exception:
        return {}

def get_public_ip():
    for service in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(service, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                ip = resp.read().decode().strip()
                if ipaddress.ip_address(ip).version == 4: return ip
        except Exception:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]

def get_server_country(ip):
    services = [
        ("http://ip-api.com/json/{}?fields=countryCode", lambda d: d.get("countryCode")),
        ("https://ipwho.is/{}", lambda d: d.get("country_code")),
        ("https://freeipapi.com/api/json/{}", lambda d: d.get("countryCode")),
    ]
    for url_tmpl, extractor in services:
        try:
            req = urllib.request.Request(url_tmpl.format(ip), headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                cc = extractor(json.loads(resp.read().decode()))
                if cc and len(cc) == 2: return cc.upper()
        except Exception:
            continue
    return None

def get_origin_and_network_info(ip):
    net_data = fetch_ripestat_safe("network-info", ip, timeout=6)
    asns = net_data.get("asns", [])
    if not asns: raise RuntimeError(f"Не удалось получить ASN для IP {ip}")
    asn = f"AS{asns[0]}" if not str(asns[0]).upper().startswith("AS") else str(asns[0])
    return asn, net_data.get("prefix")

def get_asn_prefixes(asn):
    ris_data = fetch_ripestat_safe("ris-prefixes", asn, "&types=o&af=v4", timeout=6)
    prefixes = ris_data.get("prefixes", {})
    if isinstance(prefixes, dict):
        v4 = prefixes.get("v4", {})
        if isinstance(v4, dict):
            res = v4.get("originating", [])
            if res: return res
        elif isinstance(v4, list) and v4:
            return v4
    ann_data = fetch_ripestat_safe("announced-prefixes", asn, timeout=6)
    return [p["prefix"] for p in ann_data.get("prefixes", []) if ":" not in p.get("prefix", "")]

def filter_prefixes_by_country(prefixes, target_country):
    if not target_country or not prefixes: return prefixes
    
    sample_map = {}
    batch_payload = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            first_ip = str(next(net.hosts()))
            sample_map[first_ip] = p
            batch_payload.append({"query": first_ip})
        except Exception:
            continue

    matched = set()
    batch_size = 100
    target_country = target_country.upper()
    chunks = [batch_payload[i : i + batch_size] for i in range(0, len(batch_payload), batch_size)]

    def process_chunk(chunk):
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,countryCode,status",
                data=json.dumps(chunk).encode("utf-8"),
                headers={"User-Agent": "curl/7.88.1", "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                for item in json.loads(resp.read().decode()):
                    if item.get("status") == "success" and item.get("countryCode", "").upper() == target_country:
                        ip_q = item.get("query")
                        if ip_q in sample_map: matched.add(sample_map[ip_q])
        except Exception:
            # FAIL-SAFE: При ошибке API отбрасываем чанк, чтобы избежать лавины мусорных IP
            pass

    # max_workers=5 для безопасности, чтобы не поймать 429 Too Many Requests от ip-api.com
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(chunks) or 1)) as ex:
        ex.map(process_chunk, chunks)

    return sorted(list(matched))

def generate_scan_ips(prefixes, my_ip, max_ips=0):
    ip_scan_pool = []
    seen = {my_ip}
    for p_str in prefixes:
        if max_ips > 0 and len(ip_scan_pool) >= max_ips: break
        try:
            net = ipaddress.ip_network(p_str, strict=False)
        except Exception:
            continue
            
        if net.prefixlen >= 24:
            count = 0  
            for ip in net.hosts():
                ip_s = str(ip)
                if ip_s not in seen:
                    seen.add(ip_s)
                    ip_scan_pool.append(ip_s)
                    count += 1
                    if max_ips > 0 and len(ip_scan_pool) >= max_ips: break
                    if count >= MAX_HOSTS_PER_24: break
        else:
            for s in list(net.subnets(new_prefix=24))[:MAX_SAMPLED_24_PER_LARGE_PREFIX]:
                if max_ips > 0 and len(ip_scan_pool) >= max_ips: break
                count = 0
                for ip in s.hosts():
                    ip_s = str(ip)
                    if ip_s not in seen:
                        seen.add(ip_s)
                        ip_scan_pool.append(ip_s)
                        count += 1
                        if max_ips > 0 and len(ip_scan_pool) >= max_ips: break
                        if count >= MAX_HOSTS_PER_24: break
    return ip_scan_pool


# ================= Strict Domain Validation & ASN.1 =================

def clean_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str): return None
    dom_str = dom_str.strip().lower().lstrip("*.")
    if "." not in dom_str or len(dom_str) < 4: return None
    tld = dom_str.split(".")[-1]
    if not re.match(r"^[a-z]{2,24}$", tld) or tld in BANNED_TLDS: return None
    if any(c in dom_str for c in " \t\r\n/\\:*?\"'<>|#%&={}~`!@$^()+[]"): return None
    return dom_str

def decode_tlv(data, offset):
    if offset >= len(data): return None
    tag = data[offset]
    offset += 1
    if offset >= len(data): return None
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        if offset + nbytes > len(data): return None
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    if offset + length > len(data): return None
    val = data[offset : offset + length]
    return tag, val, offset + length

def parse_x509_der(der_bytes):
    domains = set()
    if not der_bytes: return domains
    cert_tlv = decode_tlv(der_bytes, 0)
    if not cert_tlv or cert_tlv[0] != 0x30: return domains
    tbs_tlv = decode_tlv(cert_tlv[1], 0)
    if not tbs_tlv or tbs_tlv[0] != 0x30: return domains

    tbs_bytes = tbs_tlv[1]
    offset = 0
    tbs_elements = []
    while offset < len(tbs_bytes):
        tlv = decode_tlv(tbs_bytes, offset)
        if not tlv: break
        tbs_elements.append(tlv)
        offset = tlv[2]

    oid_cn = b"\x55\x04\x03"
    oid_san = b"\x55\x1d\x11"
    
    for tag, val, _ in tbs_elements:
        if tag == 0x30 and oid_cn in val:
            sub_off = 0
            while sub_off < len(val):
                rdn = decode_tlv(val, sub_off)
                if not rdn: break
                if oid_cn in rdn[1]:
                    atv_off = 0
                    while atv_off < len(rdn[1]):
                        atv = decode_tlv(rdn[1], atv_off)
                        if not atv: break
                        if oid_cn in atv[1]:
                            cn_str_tlv = decode_tlv(atv[1], 0)
                            if cn_str_tlv:
                                cn_val_tlv = decode_tlv(atv[1], cn_str_tlv[2])
                                if cn_val_tlv:
                                    try:
                                        d = clean_domain(cn_val_tlv[1].decode("utf-8", errors="ignore"))
                                        if d: domains.add(d)
                                    except Exception: pass
                        atv_off = atv[2]
                sub_off = rdn[2]

        elif (tag & 0xC0) == 0x80 and (tag & 0x1F) == 3:
            ext_seq = decode_tlv(val, 0)
            if ext_seq and ext_seq[0] == 0x30:
                e_off = 0
                while e_off < len(ext_seq[1]):
                    ext = decode_tlv(ext_seq[1], e_off)
                    if not ext: break
                    if oid_san in ext[1]:
                        ext_elem_off = 0
                        while ext_elem_off < len(ext[1]):
                            elem = decode_tlv(ext[1], ext_elem_off)
                            if not elem: break
                            if elem[0] == 0x04:
                                san_seq = decode_tlv(elem[1], 0)
                                if san_seq and san_seq[0] == 0x30:
                                    gn_off = 0
                                    while gn_off < len(san_seq[1]):
                                        gn = decode_tlv(san_seq[1], gn_off)
                                        if not gn: break
                                        if gn[0] == 0x82:
                                            try:
                                                d = clean_domain(gn[1].decode("ascii", errors="ignore"))
                                                if d: domains.add(d)
                                            except Exception: pass
                                        gn_off = gn[2]
                            ext_elem_off = elem[2]
                    e_off = ext[2]
    return domains


# ================= OSINT & Sync Resolvers =================

def get_ptr_domains(ip_str):
    domains = set()
    try:
        name, aliases, _ = socket.gethostbyaddr(ip_str)
        for h in [name] + aliases:
            d = clean_domain(h)
            if d: domains.add(d)
    except Exception:
        pass
    return domains

def get_osint_domains(ip_str):
    domains = set()
    try:
        req = urllib.request.Request(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_str}/passive_dns",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            for r in json.loads(resp.read().decode()).get("passive_dns", []):
                d = clean_domain(r.get("hostname", ""))
                if d: domains.add(d)
    except Exception:
        pass

    if not domains:
        try:
            req = urllib.request.Request(
                f"https://rapiddns.io/s/{ip_str}?full=1",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                for m in re.findall(r'">([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</a>', resp.read().decode("utf-8")):
                    d = clean_domain(m)
                    if d: domains.add(d)
        except Exception:
            pass
            
    return list(domains)[:10]

def resolve_domain_safe(domain):
    cached = DNS_CACHE.get(domain)
    if cached is not None: return cached
    ips = []
    for _ in range(2):
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            break
        except Exception:
            time.sleep(0.04)
    DNS_CACHE[domain] = ips
    return ips


# ================= Async Discovery & Verification =================

async def check_tls_async(ip_str, hostname):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_str, 443, ssl=CTX_RAW, server_hostname=hostname),
            timeout=CONNECT_TIMEOUT
        )
        der = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()
        return der
    except Exception:
        return None

async def probe_ip_target_async(ip_str, loop, executor):
    discovered_domains = set()
    
    # 1. Сбор PTR
    ptr_doms = await loop.run_in_executor(executor, get_ptr_domains, ip_str)
    discovered_domains.update(ptr_doms)

    # 2. Прямой TLS опрос
    direct_der = await check_tls_async(ip_str, ip_str)
    direct_success = False
    if direct_der:
        discovered_domains.update(parse_x509_der(direct_der))
        direct_success = True

    # 3. PTR-домены
    if ptr_doms:
        async def check_and_add(c):
            c_der = await check_tls_async(ip_str, c)
            if c_der: discovered_domains.update(parse_x509_der(c_der))
        await asyncio.gather(*(check_and_add(c) for c in ptr_doms))

    # 4. OSINT Bypass
    if not direct_success and not discovered_domains:
        is_open = False
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=1.0)
            writer.close()
            await writer.wait_closed()
            is_open = True
        except Exception:
            pass
            
        if is_open:
            osint_doms = await loop.run_in_executor(executor, get_osint_domains, ip_str)
            if osint_doms:
                # Опрашиваем по очереди. Как только один подошёл, выходим.
                for candidate in osint_doms:
                    c_der = await check_tls_async(ip_str, candidate)
                    if c_der:
                        discovered_domains.update(parse_x509_der(c_der))
                        break

    return ip_str, discovered_domains


async def verify_target_h2_async(ip_str, sni, loop, executor):
    sni = clean_domain(sni)
    if not sni: return None

    resolved_ips = await loop.run_in_executor(executor, resolve_domain_safe, sni)
    if not resolved_ips or (ip_str not in resolved_ips):
        return None

    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_str, 443, ssl=CTX_REALITY, server_hostname=sni),
            timeout=CONNECT_TIMEOUT
        )
        rtt_ms = (time.perf_counter() - t0) * 1000
        
        ssl_obj = writer.get_extra_info('ssl_object')
        negotiated_alpn = ssl_obj.selected_alpn_protocol()
        alpn_tag = negotiated_alpn if negotiated_alpn else "h2 (no ALPN)"

        writer.write(H2_PREFACE)
        writer.write(build_h2_frame(0x04, 0, 0, b""))
        writer.write(build_h2_frame(0x01, 0x05, 1, build_h2_request_headers(sni)))
        await writer.drain()

        recv_buf = bytearray()
        headers_received = {}
        data_bytes_received = 0
        is_h2_confirmed = False
        end_stream_received = False
        start_recv = time.perf_counter()

        while time.perf_counter() - start_recv < 2.5:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
                
            if not chunk: break
            recv_buf.extend(chunk)

            if recv_buf.startswith(b"HTTP/1."):
                writer.close()
                await writer.wait_closed()
                return None

            while len(recv_buf) >= 9:
                length = int.from_bytes(recv_buf[0:3], "big")
                frame_type = recv_buf[3]
                flags = recv_buf[4]
                stream_id = int.from_bytes(recv_buf[5:9], "big") & 0x7FFFFFFF

                if frame_type in (0x00, 0x01, 0x04, 0x07, 0x08):
                    is_h2_confirmed = True

                if len(recv_buf) < 9 + length: break
                payload = recv_buf[9 : 9 + length]
                del recv_buf[: 9 + length]

                if frame_type == 0x04 and not (flags & 0x01):  
                    writer.write(build_h2_frame(0x04, 0x01, 0, b""))
                    await writer.drain()
                elif frame_type == 0x01 and stream_id == 1: 
                    if flags & 0x01: end_stream_received = True
                    parsed = parse_hpack_headers(payload, flags)
                    if parsed: headers_received.update(parsed)
                elif frame_type == 0x00 and stream_id == 1: 
                    if flags & 0x01: end_stream_received = True
                    data_bytes_received += len(payload)

            if is_h2_confirmed and ":status" in headers_received:
                if end_stream_received or data_bytes_received > 0 or (time.perf_counter() - start_recv > 0.4):
                    break

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not is_h2_confirmed: return None

        return {
            "dest": f"{sni}:443",
            "sni": sni,
            "ip": ip_str,
            "rtt": round(rtt_ms, 1),
            "tls": "1.3",
            "alpn": alpn_tag,
            "status": headers_received.get(":status", "200"),
            "server": headers_received.get("server", "-"),
            "data_bytes": data_bytes_received
        }
    except Exception:
        pass
    return None


async def run_scan(ip_scan_pool, args):
    loop = asyncio.get_running_loop()
    
    # Пул потоков динамически привязан к concurrency, чтобы избежать очереди (Bottleneck)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
    concurrency = args.concurrency

    # ================= ЭТАП 1: ПРОБИНГ =================
    queue1 = asyncio.Queue()
    for ip in ip_scan_pool: queue1.put_nowait(ip)
    
    found_entries = set()
    done_count = 0
    total_ips = len(ip_scan_pool)

    async def worker_phase1():
        nonlocal done_count
        while not queue1.empty():
            try:
                ip = queue1.get_nowait()
            except asyncio.QueueEmpty:
                break
                
            ip_str, domains = await probe_ip_target_async(ip, loop, executor)
            for d in domains:
                found_entries.add((ip_str, d))
                
            done_count += 1
            if done_count % 500 == 0 or done_count == total_ips:
                print(f"\r[*] Этап 1/2: Сбор доменов (ASN.1 + OSINT): {done_count}/{total_ips} ({(done_count/total_ips)*100:.1f}%)", end="", flush=True)
            queue1.task_done()

    workers = [asyncio.create_task(worker_phase1()) for _ in range(concurrency)]
    await asyncio.gather(*workers)

    print(f"\n[+] Извлечено {len(found_entries)} чистых пар [IP <-> SNI].")
    print("[*] Этап 2/2: Строгая валидация TLS 1.3 + HTTP/2 (HEADERS, DATA, Status)...")

    # ================= ЭТАП 2: ВАЛИДАЦИЯ =================
    queue2 = asyncio.Queue()
    for entry in found_entries: queue2.put_nowait(entry)
    
    valid_targets = []

    async def worker_phase2():
        while not queue2.empty():
            try:
                ip, dom = queue2.get_nowait()
            except asyncio.QueueEmpty:
                break
                
            res = await verify_target_h2_async(ip, dom, loop, executor)
            if res:
                valid_targets.append(res)
            queue2.task_done()

    workers2 = [asyncio.create_task(worker_phase2()) for _ in range(concurrency)]
    await asyncio.gather(*workers2)

    executor.shutdown(wait=False)
    return valid_targets


def main():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # default=100 - безопасное и быстрое значение по умолчанию
    parser = argparse.ArgumentParser(description="Strict Reality Scanner (Async + OOM Safe + OSINT Bypass)")
    parser.add_argument("-c", "--country", type=str, help="Принудительно код страны (например, RU, US, NL)")
    parser.add_argument("--all", action="store_true", help="Сканировать все подсети ASN без гео-фильтра")
    parser.add_argument("--debug-ip", type=str, help="Отладка конкретного IP (например, 94.156.181.211)")
    parser.add_argument("-w", "--concurrency", type=int, default=100, help="Количество асинхронных потоков (по умолчанию: 100)")
    parser.add_argument("--max-ips", type=int, default=0, help="Жёсткий лимит общего числа сканируемых IP-адресов (0 - без лимита)")
    args = parser.parse_args()

    print("=" * 115)
    print("      RIPE REALITY SCANNER (Async + Safe Memory + OSINT Bypass)")
    print("=" * 115)

    my_ip = get_public_ip()
    print(f"[*] Внешний IP:        {my_ip}")
    print(f"[*] Параллелизм:       {args.concurrency} одновременных async-соединений")

    if args.debug_ip:
        print(f"\n[*] Точечная проверка IP: {args.debug_ip}")
        loop = asyncio.new_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
        _, doms = loop.run_until_complete(probe_ip_target_async(args.debug_ip, loop, executor))
        print(f"[+] Обнаружено доменов (ASN.1 + OSINT): {doms}")
        for d in doms:
            res = loop.run_until_complete(verify_target_h2_async(args.debug_ip, d, loop, executor))
            print(f"    - Проверка SNI '{d}': {res if res else 'ОТКЛОНЕН'}")
        sys.exit(0)

    asn, announced_prefix = get_origin_and_network_info(my_ip)
    print(f"[*] Announcing ASN:    {asn} (Локальный префикс: {announced_prefix})")

    if args.all:
        country = None
        print("[*] Фильтрация по гео: Отключена (флаг --all)")
    elif args.country:
        country = args.country.upper()
        print(f"[*] Страна сервера:    {country} (задана вручную)")
    else:
        country = get_server_country(my_ip)
        print(f"[*] Страна сервера:    {country or 'Unknown'} (GeoIP)")

    all_prefixes = get_asn_prefixes(asn)
    print(f"[*] Всего префиксов:   {len(all_prefixes)} в базе BGP")

    if args.all or not country:
        target_prefixes = all_prefixes
    else:
        target_prefixes = filter_prefixes_by_country(all_prefixes, country)
        if not target_prefixes:
            print("[-] Гео-фильтр отсёк все префиксы или API недоступно. Сканирование невозможно.")
            sys.exit(1)
        if announced_prefix and announced_prefix not in target_prefixes:
            target_prefixes.insert(0, announced_prefix)

    print(f"[+] Подсетей для сканирования: {len(target_prefixes)}")

    ip_scan_pool = generate_scan_ips(target_prefixes, my_ip, args.max_ips)
    total_ips = len(ip_scan_pool)
    print(f"[*] Подготовлено {total_ips} IP для сканирования...")

    if total_ips == 0:
        sys.exit(0)

    valid_targets = asyncio.run(run_scan(ip_scan_pool, args))

    dedup = {}
    for item in valid_targets:
        key = (item["sni"], item["ip"])
        if key not in dedup or dedup[key]["rtt"] > item["rtt"]:
            dedup[key] = item

    results = sorted(dedup.values(), key=lambda x: x["rtt"])

    print(f"\n[+] Найдено валидных HTTP/2 целей: {len(results)}\n")
    if not results:
        print("[-] Подходящих HTTP/2 целей не обнаружено.")
        sys.exit(0)

    fmt = "{:<36} | {:<15} | {:<13} | {:<5} | {:<9} | {:<20} | {:<7}"
    print(fmt.format("Цель (SNI)", "IP адрес", "ALPN", "HTTP", "DATA", "Сервер", "RTT"))
    print("-" * 115)
    for r in results:
        data_str = f"{r['data_bytes']} B" if r["data_bytes"] > 0 else "0 B"
        print(fmt.format(
            r["sni"][:36],
            r["ip"],
            r["alpn"][:13],
            r["status"],
            data_str,
            r["server"][:20],
            f"{r['rtt']} ms"
        ))

    best = results[0]
    print("\n" + "=" * 115)
    print("            РЕКОМЕНДУЕМАЯ КОНФИГУРАЦИЯ REALITY (HTTP/2)")
    print("=" * 115)
    print(f'"dest": "{best["dest"]}",')
    print('"serverNames": [')
    print(f'  "{best["sni"]}"')
    print(']')
    print(f"\nПараметры: ALPN: {best['alpn']}, HTTP Status: {best['status']}, Server: {best['server']}, Body: {best['data_bytes']} B, RTT: {best['rtt']} ms")

if __name__ == "__main__":
    main()
