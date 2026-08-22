#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.request

CONNECT_TIMEOUT = 2.5
MAX_WORKERS = 40
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
DNS_LOCK = threading.Lock()

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
            if not isinstance(node, dict):
                node = HUFFMAN_TREE
            node = node.get(bit)
            if node is None:
                node = HUFFMAN_TREE
                continue
            if "sym" in node:
                sym = node["sym"]
                if sym == 256:
                    return out.decode("latin1", errors="ignore")
                out.append(sym)
                node = HUFFMAN_TREE
    return out.decode("latin1", errors="ignore")


def decode_hpack_int(data, offset, prefix_bits):
    max_prefix = (1 << prefix_bits) - 1
    if offset >= len(data):
        return 0, offset
    val = data[offset] & max_prefix
    offset += 1
    if val < max_prefix:
        return val, offset
    m = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        val += (b & 0x7F) << m
        m += 7
        if not (b & 0x80):
            break
    return val, offset


def decode_hpack_string(data, offset):
    if offset >= len(data):
        return "", offset
    huffman = bool(data[offset] & 0x80)
    str_len, offset = decode_hpack_int(data, offset, 7)
    if offset + str_len > len(data):
        return "", offset
    raw_bytes = data[offset : offset + str_len]
    offset += str_len
    if huffman:
        return decode_huffman(raw_bytes), offset
    return raw_bytes.decode("latin1", errors="ignore"), offset


def parse_hpack_headers(payload, flags=0):
    headers = {}
    try:
        offset = 0
        pad_len = 0
        if flags & 0x08:
            if offset < len(payload):
                pad_len = payload[offset]
                offset += 1
        if flags & 0x20:
            offset += 5

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
                if ipaddress.ip_address(ip).version == 4:
                    return ip
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
                res = json.loads(resp.read().decode())
                cc = extractor(res)
                if cc and len(cc) == 2:
                    return cc.upper()
        except Exception:
            continue
    return None


def get_origin_and_network_info(ip):
    net_data = fetch_ripestat_safe("network-info", ip, timeout=6)
    asns = net_data.get("asns", [])
    if not asns:
        raise RuntimeError(f"Не удалось получить ASN для IP {ip}")
    asn = f"AS{asns[0]}" if not str(asns[0]).upper().startswith("AS") else str(asns[0])
    announced_prefix = net_data.get("prefix")
    return asn, announced_prefix


def get_asn_prefixes(asn):
    ris_data = fetch_ripestat_safe("ris-prefixes", asn, "&types=o&af=v4", timeout=6)
    prefixes = ris_data.get("prefixes", {})
    if isinstance(prefixes, dict):
        v4 = prefixes.get("v4", {})
        if isinstance(v4, dict):
            res = v4.get("originating", [])
            if res:
                return res
        elif isinstance(v4, list) and v4:
            return v4
    ann_data = fetch_ripestat_safe("announced-prefixes", asn, timeout=6)
    raw_list = ann_data.get("prefixes", [])
    return [p["prefix"] for p in raw_list if ":" not in p.get("prefix", "")]


def filter_prefixes_by_country(prefixes, target_country):
    if not target_country or not prefixes:
        return prefixes
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

    matched = []
    batch_size = 100
    for i in range(0, len(batch_payload), batch_size):
        chunk = batch_payload[i : i + batch_size]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,countryCode,status",
                data=json.dumps(chunk).encode("utf-8"),
                headers={"User-Agent": "curl/7.88.1", "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                res = json.loads(resp.read().decode())
                for item in res:
                    if item.get("status") == "success" and item.get("countryCode", "").upper() == target_country.upper():
                        ip_q = item.get("query")
                        if ip_q in sample_map:
                            matched.append(sample_map[ip_q])
        except Exception:
            for item in chunk:
                ip_q = item.get("query")
                if ip_q in sample_map:
                    matched.append(sample_map[ip_q])

    return sorted(list(set(matched)))


# ================= Strict Domain Validation & ASN.1 =================

def clean_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str):
        return None
    dom_str = dom_str.strip().lower().lstrip("*.")
    if "." not in dom_str or len(dom_str) < 4:
        return None
    
    parts = dom_str.split(".")
    tld = parts[-1]
    
    # Строгая проверка TLD: только буквы от 2 до 24 символов, не из черного списка
    if not re.match(r"^[a-z]{2,24}$", tld) or tld in BANNED_TLDS:
        return None
    
    if any(c in dom_str for c in " \t\r\n/\\:*?\"'<>|#%&={}~`!@$^()+[]"):
        return None
        
    return dom_str


def decode_tlv(data, offset):
    if offset >= len(data):
        return None
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return None
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        if offset + nbytes > len(data):
            return None
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    if offset + length > len(data):
        return None
    val = data[offset : offset + length]
    return tag, val, offset + length


def parse_x509_der(der_bytes):
    domains = set()
    if not der_bytes:
        return domains
    cert_tlv = decode_tlv(der_bytes, 0)
    if not cert_tlv or cert_tlv[0] != 0x30:
        return domains
    tbs_tlv = decode_tlv(cert_tlv[1], 0)
    if not tbs_tlv or tbs_tlv[0] != 0x30:
        return domains

    tbs_bytes = tbs_tlv[1]
    offset = 0
    tbs_elements = []
    while offset < len(tbs_bytes):
        tlv = decode_tlv(tbs_bytes, offset)
        if not tlv:
            break
        tbs_elements.append(tlv)
        offset = tlv[2]

    # 1. Subject Common Name (CN, OID 2.5.4.3)
    oid_cn = b"\x55\x04\x03"
    for tag, val, _ in tbs_elements:
        if tag == 0x30 and oid_cn in val:
            sub_off = 0
            while sub_off < len(val):
                rdn = decode_tlv(val, sub_off)
                if not rdn:
                    break
                if oid_cn in rdn[1]:
                    atv_off = 0
                    while atv_off < len(rdn[1]):
                        atv = decode_tlv(rdn[1], atv_off)
                        if not atv:
                            break
                        if oid_cn in atv[1]:
                            cn_str_tlv = decode_tlv(atv[1], 0)
                            if cn_str_tlv:
                                cn_val_tlv = decode_tlv(atv[1], cn_str_tlv[2])
                                if cn_val_tlv:
                                    try:
                                        d = clean_domain(cn_val_tlv[1].decode("utf-8", errors="ignore"))
                                        if d:
                                            domains.add(d)
                                    except Exception:
                                        pass
                        atv_off = atv[2]
                sub_off = rdn[2]

    # 2. SubjectAltName (SAN, OID 2.5.29.17) -> tag 0x82 (dNSName ONLY)
    oid_san = b"\x55\x1d\x11"
    for tag, val, _ in tbs_elements:
        if (tag & 0xC0) == 0x80 and (tag & 0x1F) == 3:
            ext_seq = decode_tlv(val, 0)
            if ext_seq and ext_seq[0] == 0x30:
                e_off = 0
                while e_off < len(ext_seq[1]):
                    ext = decode_tlv(ext_seq[1], e_off)
                    if not ext:
                        break
                    if oid_san in ext[1]:
                        ext_elem_off = 0
                        while ext_elem_off < len(ext[1]):
                            elem = decode_tlv(ext[1], ext_elem_off)
                            if not elem:
                                break
                            if elem[0] == 0x04:
                                san_seq = decode_tlv(elem[1], 0)
                                if san_seq and san_seq[0] == 0x30:
                                    gn_off = 0
                                    while gn_off < len(san_seq[1]):
                                        gn = decode_tlv(san_seq[1], gn_off)
                                        if not gn:
                                            break
                                        if gn[0] == 0x82:  # Строго dNSName
                                            try:
                                                d = clean_domain(gn[1].decode("ascii", errors="ignore"))
                                                if d:
                                                    domains.add(d)
                                            except Exception:
                                                pass
                                        gn_off = gn[2]
                            ext_elem_off = elem[2]
                    e_off = ext[2]
    return domains


def get_ptr_domains(ip_str):
    domains = set()
    try:
        name, aliases, _ = socket.gethostbyaddr(ip_str)
        for h in [name] + aliases:
            d = clean_domain(h)
            if d:
                domains.add(d)
    except Exception:
        pass
    return domains


# ================= Discovery & Verification =================

def probe_ip_target(ip_str):
    discovered_domains = set()
    
    # 1. PTR
    ptr_doms = get_ptr_domains(ip_str)
    discovered_domains.update(ptr_doms)

    # 2. Прямой TLS опрос (без SNI)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip_str, 443))
        with CTX_RAW.wrap_socket(sock, server_hostname=ip_str) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if der:
                discovered_domains.update(parse_x509_der(der))
    except Exception:
        pass

    # 3. Дополнительный опрос с найденными через PTR SNI
    for candidate in list(ptr_doms):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((ip_str, 443))
            with CTX_RAW.wrap_socket(sock, server_hostname=candidate) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    discovered_domains.update(parse_x509_der(der))
        except Exception:
            pass

    return ip_str, discovered_domains


def resolve_domain_safe(domain):
    with DNS_LOCK:
        if domain in DNS_CACHE:
            return DNS_CACHE[domain]

    ips = []
    for _ in range(2):
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            break
        except Exception:
            time.sleep(0.04)

    with DNS_LOCK:
        DNS_CACHE[domain] = ips
    return ips


def verify_target_h2(ip_str, sni):
    sni = clean_domain(sni)
    if not sni:
        return None

    # 1. СТРОГАЯ DNS ПРОВЕРКА: IP домена обязан совпадать с IP сканирования
    resolved_ips = resolve_domain_safe(sni)
    if not resolved_ips or (ip_str not in resolved_ips):
        return None

    # 2. Рукопожатие TLS 1.3 + Native HTTP/2
    try:
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip_str, 443))

        with CTX_REALITY.wrap_socket(sock, server_hostname=sni) as ssock:
            rtt_ms = (time.perf_counter() - t0) * 1000
            negotiated_alpn = ssock.selected_alpn_protocol()
            alpn_tag = negotiated_alpn if negotiated_alpn else "h2 (no ALPN)"

            # Отправляем Client Preface + SETTINGS + HEADERS
            ssock.sendall(H2_PREFACE)
            ssock.sendall(build_h2_frame(0x04, 0, 0, b""))  # SETTINGS
            req_headers = build_h2_request_headers(sni)
            ssock.sendall(build_h2_frame(0x01, 0x05, 1, req_headers))  # HEADERS (END_STREAM | END_HEADERS)

            recv_buf = bytearray()
            headers_received = {}
            data_bytes_received = 0
            is_h2_confirmed = False
            start_recv = time.perf_counter()

            while time.perf_counter() - start_recv < 2.5:
                try:
                    chunk = ssock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                recv_buf.extend(chunk)

                if recv_buf.startswith(b"HTTP/1."):
                    return None

                while len(recv_buf) >= 9:
                    length = int.from_bytes(recv_buf[0:3], "big")
                    frame_type = recv_buf[3]
                    flags = recv_buf[4]
                    stream_id = int.from_bytes(recv_buf[5:9], "big") & 0x7FFFFFFF

                    if frame_type in (0x00, 0x01, 0x04, 0x07, 0x08):
                        is_h2_confirmed = True

                    if len(recv_buf) < 9 + length:
                        break

                    payload = recv_buf[9 : 9 + length]
                    del recv_buf[: 9 + length]

                    if frame_type == 0x04 and not (flags & 0x01):  # SETTINGS -> отвечаем ACK
                        ssock.sendall(build_h2_frame(0x04, 0x01, 0, b""))

                    elif frame_type == 0x01 and stream_id == 1:  # HEADERS
                        parsed = parse_hpack_headers(payload, flags)
                        if parsed:
                            headers_received.update(parsed)

                    elif frame_type == 0x00 and stream_id == 1:  # DATA
                        data_bytes_received += len(payload)

                # Завершаем, если получен статус и данные (или поток закрыт)
                if is_h2_confirmed and ":status" in headers_received:
                    if data_bytes_received > 0 or (time.perf_counter() - start_recv > 0.4):
                        break

            if not is_h2_confirmed:
                return None

            http_status = headers_received.get(":status", "200")
            server_hdr = headers_received.get("server", "-")

            return {
                "dest": f"{sni}:443",
                "sni": sni,
                "ip": ip_str,
                "rtt": round(rtt_ms, 1),
                "tls": "1.3",
                "alpn": alpn_tag,
                "status": http_status,
                "server": server_hdr,
                "data_bytes": data_bytes_received
            }

    except Exception:
        pass
    return None


def generate_scan_ips(prefixes, my_ip):
    ip_scan_pool = []
    for p_str in prefixes:
        net = ipaddress.ip_network(p_str, strict=False)
        if net.prefixlen >= 24:
            hosts = [str(ip) for ip in net.hosts() if str(ip) != my_ip]
            ip_scan_pool.extend(hosts[:MAX_HOSTS_PER_24])
        else:
            subnets_24 = list(net.subnets(new_prefix=24))
            sampled_subnets = subnets_24[:MAX_SAMPLED_24_PER_LARGE_PREFIX]
            for s in sampled_subnets:
                hosts = [str(ip) for ip in s.hosts() if str(ip) != my_ip]
                ip_scan_pool.extend(hosts)
    return list(dict.fromkeys(ip_scan_pool))


def main():
    parser = argparse.ArgumentParser(description="Strict Reality Scanner (Clean HTTP/2 & Strict DNS)")
    parser.add_argument("-c", "--country", type=str, help="Принудительно код страны (например, RU, US, NL)")
    parser.add_argument("--all", action="store_true", help="Сканировать все подсети ASN без гео-фильтра")
    parser.add_argument("--debug-ip", type=str, help="Отладка конкретного IP (например, 94.156.181.211)")
    args = parser.parse_args()

    print("=" * 115)
    print("      RIPE REALITY SCANNER (Strict X.509 ASN.1 + Native HTTP/2 Engine)")
    print("=" * 115)

    my_ip = get_public_ip()
    print(f"[*] Внешний IP:        {my_ip}")

    if args.debug_ip:
        print(f"\n[*] Точечная проверка IP: {args.debug_ip}")
        _, doms = probe_ip_target(args.debug_ip)
        print(f"[+] Обнаружено доменов (ASN.1): {doms}")
        for d in doms:
            res = verify_target_h2(args.debug_ip, d)
            print(f"    - Проверка SNI '{d}': {res if res else 'ОТКЛОНЕН'}")
        sys.exit(0)

    # 1. ASN и Префикс
    asn, announced_prefix = get_origin_and_network_info(my_ip)
    print(f"[*] Announcing ASN:    {asn} (Локальный префикс: {announced_prefix})")

    # 2. Локация хоста
    if args.all:
        country = None
        print("[*] Фильтрация по гео: Отключена (флаг --all)")
    elif args.country:
        country = args.country.upper()
        print(f"[*] Страна сервера:    {country} (задана вручную)")
    else:
        country = get_server_country(my_ip)
        print(f"[*] Страна сервера:    {country or 'Unknown'} (GeoIP)")

    # 3. Префиксы
    all_prefixes = get_asn_prefixes(asn)
    print(f"[*] Всего префиксов:   {len(all_prefixes)} в базе BGP")

    # 4. Фильтрация
    if args.all or not country:
        target_prefixes = all_prefixes
    else:
        target_prefixes = filter_prefixes_by_country(all_prefixes, country)
        if announced_prefix and announced_prefix not in target_prefixes:
            target_prefixes.insert(0, announced_prefix)

    print(f"[+] Подсетей для сканирования: {len(target_prefixes)}")

    # 5. Пул IP
    ip_scan_pool = generate_scan_ips(target_prefixes, my_ip)
    total_ips = len(ip_scan_pool)
    print(f"[*] Подготовлено {total_ips} IP для сканирования...")

    # 6. Сканирование сертификатов и PTR
    found_entries = []
    done_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe_ip_target, ip): ip for ip in ip_scan_pool}
        for f in concurrent.futures.as_completed(futures):
            done_count += 1
            if done_count % 500 == 0 or done_count == total_ips:
                print(f"\r[*] Этап 1/2: Сбор доменов (ASN.1 + PTR): {done_count}/{total_ips} ({(done_count/total_ips)*100:.1f}%)", end="", flush=True)
            ip_str, domains = f.result()
            for dom in domains:
                found_entries.append((ip_str, dom))

    found_entries = list(set(found_entries))
    print(f"\n[+] Извлечено {len(found_entries)} чистых пар [IP <-> SNI].")
    print("[*] Этап 2/2: Строгая валидация TLS 1.3 + HTTP/2 (HEADERS, DATA, Status)...")

    # 7. Валидация HTTP/2
    valid_targets = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(verify_target_h2, ip, dom) for ip, dom in found_entries]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                valid_targets.append(res)

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
