#!/usr/bin/env python3
"""
generate_test_files.py
CSL-G17 · RTU 7CS4-22 Experiment 3

Generates self-owned dummy test targets for dictionary & brute-force
password recovery experiments.  No external OS binaries required.

Targets created in ./test_targets/:
  own_dict.zip  – ZipCrypto encrypted ZIP, password: "Jaipur2026"
  own_pin.zip   – ZipCrypto encrypted ZIP, password: "7492"
  own_rc4.pdf   – RC4-128 encrypted PDF,   password: "skit@123"
  own_aes.pdf   – AES-256 encrypted PDF,   password: "net99"
  wordlist.txt  – 460+ base words for dictionary attacks
"""

import os
import struct
import zlib
import time

# ═══════════════════════════════════════════════════════════════════════
#  Pure-Python PKWARE ZipCrypto Cipher
# ═══════════════════════════════════════════════════════════════════════

def _make_crc_table():
    """Build the standard CRC-32 lookup table (poly 0xEDB88320)."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return table

_CRC_TABLE = _make_crc_table()


class _ZipCryptoCipher:
    """PKWARE traditional (ZipCrypto) stream cipher – pure Python.

    Implements the encryption algorithm described in APPNOTE.TXT §XI
    so that encrypted ZIPs can be created without an external ``zip``
    binary.  Python's :mod:`zipfile` decrypter is fully compatible.
    """

    def __init__(self, password: bytes):
        self.key0 = 0x12345678
        self.key1 = 0x23456789
        self.key2 = 0x34567890
        for b in password:
            self._update_keys(b)

    # -- internal helpers --------------------------------------------------

    def _update_keys(self, b: int):
        self.key0 = (_CRC_TABLE[(self.key0 ^ b) & 0xFF]
                     ^ (self.key0 >> 8)) & 0xFFFFFFFF
        self.key1 = ((self.key1 + (self.key0 & 0xFF))
                     * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = (_CRC_TABLE[(self.key2 ^ ((self.key1 >> 24) & 0xFF)) & 0xFF]
                     ^ (self.key2 >> 8)) & 0xFFFFFFFF

    def _stream_byte(self) -> int:
        temp = (self.key2 | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    # -- public API --------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext*; cipher state advances (streaming)."""
        result = bytearray(len(plaintext))
        for i, b in enumerate(plaintext):
            k = self._stream_byte()
            result[i] = b ^ k
            self._update_keys(b)
        return bytes(result)


# ═══════════════════════════════════════════════════════════════════════
#  Encrypted ZIP File Builder
# ═══════════════════════════════════════════════════════════════════════

def _dos_datetime():
    """Current local time → DOS (time, date) uint16 pair."""
    t = time.localtime()
    dos_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    dos_date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    return dos_time, dos_date


def create_encrypted_zip(zip_path: str, entries: dict, password: str):
    """Create a PKWARE ZipCrypto-encrypted ZIP file.

    Parameters
    ----------
    zip_path : str
        Output file path.
    entries : dict[str, bytes]
        ``{archive_filename: uncompressed_content}``.
    password : str
        Encryption password.
    """
    pwd = password.encode('utf-8')
    dos_time, dos_date = _dos_datetime()

    local_parts:   list[bytes] = []
    central_parts: list[bytes] = []
    offset = 0

    for fname, content in entries.items():
        fname_b = fname.encode('utf-8')
        crc = zlib.crc32(content) & 0xFFFFFFFF

        # Raw deflate (wbits=-15 → no zlib/gzip header)
        comp = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION,
                                zlib.DEFLATED, -15)
        compressed = comp.compress(content) + comp.flush()

        # Fall back to STORED when deflate is larger
        if len(compressed) >= len(content):
            compressed = content
            method = 0        # STORED
        else:
            method = 8        # DEFLATED

        # 12-byte encryption header: 11 random bytes + CRC check byte
        header_plain = bytearray(os.urandom(11))
        header_plain.append((crc >> 24) & 0xFF)

        cipher      = _ZipCryptoCipher(pwd)
        enc_header  = cipher.encrypt(bytes(header_plain))
        enc_data    = cipher.encrypt(compressed)        # state carries over

        enc_comp_sz = 12 + len(compressed)

        # --- Local File Header (30 bytes + filename) ---
        local_hdr = struct.pack(
            '<4sHHHHHIIIHH',
            b'PK\x03\x04',       # signature
            20,                   # version needed to extract
            0x0001,               # general-purpose bit flag (encrypted)
            method,               # compression method
            dos_time, dos_date,
            crc,
            enc_comp_sz,          # compressed size (incl. 12-byte header)
            len(content),         # uncompressed size
            len(fname_b),         # filename length
            0,                    # extra field length
        ) + fname_b + enc_header + enc_data

        local_parts.append(local_hdr)

        # --- Central Directory File Header (46 bytes + filename) ---
        cd_hdr = struct.pack(
            '<4sHHHHHHIIIHHHHHII',
            b'PK\x01\x02',       # signature
            20,                   # version made by
            20,                   # version needed
            0x0001,               # flags
            method,
            dos_time, dos_date,
            crc,
            enc_comp_sz,
            len(content),
            len(fname_b),
            0, 0, 0, 0,          # extra / comment / disk# / internal attrs
            0x00000020,           # external attrs (archive bit)
            offset,               # relative offset of local header
        ) + fname_b

        central_parts.append(cd_hdr)
        offset += len(local_hdr)

    # --- End of Central Directory Record (22 bytes) ---
    cd_offset = offset
    cd_size   = sum(len(c) for c in central_parts)
    n         = len(entries)

    eocd = struct.pack(
        '<4sHHHHIIH',
        b'PK\x05\x06',
        0, 0, n, n,
        cd_size, cd_offset, 0,
    )

    with open(zip_path, 'wb') as f:
        for part in local_parts:
            f.write(part)
        for part in central_parts:
            f.write(part)
        f.write(eocd)


# ═══════════════════════════════════════════════════════════════════════
#  Encrypted PDF Builder (pypdf)
# ═══════════════════════════════════════════════════════════════════════

def create_encrypted_pdf(pdf_path: str, text: str,
                         password: str, algorithm: str):
    """Create an encrypted single-page PDF with *algorithm*."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)   # US Letter
    writer.add_metadata({
        '/Title':   'CSL-G17 Test Document',
        '/Subject': text,
        '/Author':  'CSL-G17 Generator',
    })
    writer.encrypt(password, algorithm=algorithm)

    with open(pdf_path, 'wb') as f:
        writer.write(f)


# ═══════════════════════════════════════════════════════════════════════
#  Wordlist Generator (460+ base words)
# ═══════════════════════════════════════════════════════════════════════

def generate_wordlist(path: str) -> int:
    """Generate *wordlist.txt* with 460+ base words.  Returns count."""
    words = [
        # ── Common passwords ──────────────────────────────────────────
        "password", "admin", "root", "user", "test", "hello", "world",
        "letmein", "welcome", "monkey", "dragon", "master", "qwerty",
        "abc", "login", "shadow", "sunshine", "princess", "football",
        "charlie", "access", "thunder", "matrix", "trustno",
        "ranger", "batman", "soccer", "hunter", "buster", "george",
        "pepper", "daniel", "michael", "andrew", "joshua", "thomas",
        "robert", "jordan", "maggie", "ginger", "cookie",
        "summer", "winter", "spring", "autumn", "secret",
        "iloveyou", "baseball", "passw0rd", "starwars", "ashley",

        # ── Indian context / RTU / Rajasthan ──────────────────────────
        "jaipur", "rajasthan", "skit", "rtu", "kota", "udaipur",
        "jodhpur", "bikaner", "ajmer", "pushkar", "india", "delhi",
        "mumbai", "bangalore", "chennai", "hyderabad", "kolkata",
        "pune", "ahmedabad", "lucknow", "bhopal", "patna", "ranchi",
        "guwahati", "shimla", "dehradun", "chandigarh", "agra",
        "varanasi", "amritsar", "jaisalmer", "mount", "abu",
        "mandir", "mahal", "fort", "palace", "lake", "desert",
        "camel", "sand", "haveli", "bazaar", "chowk", "gate",
        "temple", "garden", "museum", "station", "campus",
        "hostel", "library", "canteen", "semester", "exam",
        "btech", "mtech", "cyber", "security", "lab",
        "project", "viva", "marks", "grade", "topper",
        "namaste", "diwali", "holi", "ganesh", "krishna",

        # ── Cyber-security terms ──────────────────────────────────────
        "cipher", "crypto", "net", "hack", "secure", "firewall", "network",
        "protocol", "encrypt", "decrypt", "malware", "phishing",
        "trojan", "virus", "worm", "exploit", "vulnerability",
        "breach", "attack", "defense", "shield", "guard",
        "token", "hash", "salt", "nonce", "key", "lock",
        "brute", "force", "dictionary", "rainbow", "table",
        "packet", "sniffer", "proxy", "tunnel", "vpn",
        "ssl", "tls", "aes", "rsa", "des", "sha",
        "md5", "hmac", "oauth", "jwt", "xss", "sql",
        "injection", "overflow", "buffer", "stack", "heap",
        "kernel", "shell", "payload", "reverse", "bind",
        "scan", "port", "ping", "trace", "route",
        "forensic", "incident", "response", "audit", "compliance",
        "policy", "risk", "threat", "asset", "control",
        "pentest", "recon", "osint", "sigint", "humint",
        "stealth", "covert", "overt", "passive", "active",
        "ransomware", "spyware", "adware", "rootkit", "botnet",
        "keylogger", "backdoor", "sandbox", "honeypot", "darkweb",

        # ── Technology & programming ──────────────────────────────────
        "python", "java", "linux", "windows", "server",
        "database", "cloud", "docker", "kubernetes", "algorithm",
        "function", "variable", "program", "compile", "debug",
        "binary", "source", "code", "script", "module",
        "class", "object", "method", "array", "list",
        "string", "integer", "float", "boolean", "null",
        "loop", "condition", "branch", "merge", "commit",
        "deploy", "build", "release", "version", "patch",
        "api", "rest", "json", "xml", "html",
        "css", "react", "node", "flask", "django",
        "mongo", "redis", "mysql", "postgres", "sqlite",
        "git", "github", "gitlab", "bitbucket", "repo",
        "terminal", "console", "editor", "plugin", "config",
        "tensor", "neural", "model", "train", "predict",

        # ── Networking ────────────────────────────────────────────────
        "router", "switch", "hub", "bridge", "modem",
        "ethernet", "wifi", "bluetooth", "zigbee", "lora",
        "tcp", "udp", "http", "https", "ftp",
        "ssh", "telnet", "smtp", "pop", "imap",
        "dns", "dhcp", "nat", "vlan", "subnet",
        "gateway", "broadcast", "unicast", "multicast", "anycast",
        "latency", "bandwidth", "throughput", "jitter", "loss",
        "socket", "stream", "datagram", "frame", "segment",

        # ── Common English words ──────────────────────────────────────
        "apple", "banana", "cherry", "orange", "mango",
        "grape", "melon", "peach", "berry", "lemon",
        "house", "flower", "music", "dance", "sport",
        "champion", "brilliant", "diamond", "golden", "silver",
        "bronze", "platinum", "crystal", "marble", "stone",
        "river", "ocean", "mountain", "valley", "forest",
        "eagle", "falcon", "hawk", "tiger", "lion",
        "wolf", "bear", "shark", "whale", "cobra",
        "phoenix", "griffin", "unicorn", "pegasus", "centaur",
        "storm", "blaze", "frost", "light",
        "dark", "bright", "swift", "brave", "bold",
        "noble", "royal", "grand", "prime", "alpha",
        "beta", "gamma", "delta", "omega", "sigma",
        "nova", "star", "moon", "solar", "lunar",
        "cosmic", "nebula", "quasar", "pulsar", "orbit",
        "rocket", "space", "galaxy", "planet", "comet",
        "electric", "magnetic", "quantum", "atomic", "nuclear",
        "laser", "radar", "sonar", "fiber", "optic",
        "carbon", "silicon", "oxygen", "hydrogen", "helium",

        # ── Short / PIN-adjacent / mixed ──────────────────────────────
        "net", "pin", "pass", "word", "door",
        "open", "close", "start", "stop", "reset",
        "enter", "exit", "begin", "final", "first",
        "last", "next", "back", "home", "away",
        "safe", "danger", "warn", "alert", "alarm",
        "red", "blue", "green", "black", "white",
        "zero", "one", "two", "three", "four",
        "five", "six", "seven", "eight", "nine",
        "ten", "hundred", "thousand", "million", "billion",
        "north", "south", "east", "west", "center",
        "top", "bottom", "left", "right", "middle",
        "day", "night", "dawn", "dusk", "noon",
        "rain", "snow", "wind", "fire", "water",
        "earth", "air", "metal", "wood", "glass",
        "steel", "iron", "copper", "gold", "jade",

        # ── Names ─────────────────────────────────────────────────────
        "alice", "bob", "carol", "dave", "eve",
        "frank", "grace", "henry", "irene", "jack",
        "kevin", "laura", "nancy", "oscar", "peter",
        "rachel", "steve", "tina", "victor", "wendy",
        "arjun", "priya", "rahul", "sneha", "amit",
        "neha", "vikram", "pooja", "rohit", "anita",
        "suresh", "kavita", "deepak", "sunita", "rajesh",
        "meera", "arun", "divya", "manoj", "swati",
    ]

    # De-duplicate preserving order
    seen = set()
    unique = []
    for w in words:
        wl = w.lower()
        if wl not in seen:
            seen.add(wl)
            unique.append(wl)

    with open(path, 'w') as f:
        f.write('\n'.join(unique) + '\n')

    return len(unique)


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'test_targets')
    os.makedirs(target_dir, exist_ok=True)

    print("=" * 62)
    print("  CSL-G17 · Test-Target Generator")
    print("=" * 62)

    # 1 ── own_dict.zip  (password: Jaipur2026) ────────────────────────
    p = os.path.join(target_dir, 'own_dict.zip')
    create_encrypted_zip(
        p,
        {'secret.txt':
         b'CSL-G17: This file is protected with password Jaipur2026.\n'},
        'Jaipur2026',
    )
    print(f"  [+] {p}\n      password = Jaipur2026   (ZipCrypto)")

    # 2 ── own_pin.zip  (password: 7492) ───────────────────────────────
    p = os.path.join(target_dir, 'own_pin.zip')
    create_encrypted_zip(
        p,
        {'pin.txt':
         b'CSL-G17: 4-digit PIN brute-force target.\n'},
        '7492',
    )
    print(f"  [+] {p}\n      password = 7492         (ZipCrypto)")

    # 3 ── own_rc4.pdf  (password: skit@123, RC4-128) ──────────────────
    p = os.path.join(target_dir, 'own_rc4.pdf')
    create_encrypted_pdf(
        p,
        'CSL-G17 RC4-128 test document.',
        'skit@123',
        'RC4-128',
    )
    print(f"  [+] {p}\n      password = skit@123     (PDF RC4-128)")

    # 4 ── own_aes.pdf  (password: net99, AES-256) ─────────────────────
    p = os.path.join(target_dir, 'own_aes.pdf')
    create_encrypted_pdf(
        p,
        'CSL-G17 AES-256 test document.',
        'net99',
        'AES-256',
    )
    print(f"  [+] {p}\n      password = net99        (PDF AES-256)")

    # 5 ── wordlist.txt ────────────────────────────────────────────────
    p = os.path.join(target_dir, 'wordlist.txt')
    n = generate_wordlist(p)
    print(f"  [+] {p}\n      {n} base words")

    print()
    print("=" * 62)
    print("  All test targets generated successfully ✓")
    print("=" * 62)


if __name__ == '__main__':
    main()
