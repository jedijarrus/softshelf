"""
CRX3-Packer + Extension-ID-Ableitung in reinem Python (kein Chrome noetig).

CRX3-Format:
    b"Cr24" + u32le(3) + u32le(header_len) + header + zip_payload

    header = CrxFileHeader-Protobuf:
        field 2  (sha256_with_rsa): AsymmetricKeyProof { public_key=1, signature=2 }
        field 10000 (signed_header_data): SignedData { crx_id=1 (16 bytes) }

    Signatur = RSA-PKCS1v15-SHA256 ueber:
        b"CRX3 SignedData\x00" + u32le(len(signed_header_data)) + signed_header_data + zip_payload

Extension-ID = erste 16 Bytes von SHA256(DER-SubjectPublicKeyInfo),
jedes Nibble (0-f) gemappt auf a-p.  (Chromium-Konvention.)

Genutzt von routes/admin.py (upload-extension) und main.py (CRX-Hosting).
"""
import hashlib
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ── manuelle Protobuf-Helfer (winziges, fixes Schema) ────────────────────────
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _ld_field(field_no: int, data: bytes) -> bytes:
    """length-delimited Feld (wire type 2): tag + len + data."""
    tag = (field_no << 3) | 2
    return _varint(tag) + _varint(len(data)) + data


# ── Key-Handling ─────────────────────────────────────────────────────────────
def generate_private_key_pem() -> str:
    """Neuer RSA-2048-Key als PEM-String (zum Speichern pro Extension)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _load_key(private_key_pem: str):
    return serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )


def _der_pubkey(priv) -> bytes:
    """DER-kodierte SubjectPublicKeyInfo des Public Keys."""
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def crx_id_bytes(der_pubkey: bytes) -> bytes:
    """16-Byte crx_id = SHA256(DER-Pubkey)[:16]."""
    return hashlib.sha256(der_pubkey).digest()[:16]


def extension_id(der_pubkey: bytes) -> str:
    """32-Zeichen Chromium-Extension-ID (a-p) aus dem Public Key."""
    digest = hashlib.sha256(der_pubkey).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def extension_id_from_pem(private_key_pem: str) -> str:
    return extension_id(_der_pubkey(_load_key(private_key_pem)))


# ── CRX3-Packer ──────────────────────────────────────────────────────────────
def pack_crx(zip_bytes: bytes, private_key_pem: str) -> bytes:
    """Baut eine signierte CRX3 aus den ZIP-Bytes + privatem Key."""
    priv = _load_key(private_key_pem)
    der_pub = _der_pubkey(priv)
    cid = crx_id_bytes(der_pub)

    # SignedData { crx_id = 1 }
    signed_header_data = _ld_field(1, cid)

    # Signatur ueber Praefix + len + signed_header_data + payload
    to_sign = (
        b"CRX3 SignedData\x00"
        + struct.pack("<I", len(signed_header_data))
        + signed_header_data
        + zip_bytes
    )
    signature = priv.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    # AsymmetricKeyProof { public_key = 1, signature = 2 }
    proof = _ld_field(1, der_pub) + _ld_field(2, signature)

    # CrxFileHeader { sha256_with_rsa = 2 (repeated); signed_header_data = 10000 }
    header = _ld_field(2, proof) + _ld_field(10000, signed_header_data)

    return (
        b"Cr24"
        + struct.pack("<I", 3)
        + struct.pack("<I", len(header))
        + header
        + zip_bytes
    )


def crx_id_from_crx(crx_bytes: bytes) -> str | None:
    """Liest die Extension-ID aus dem Public Key im CRX3-Header (zur Validierung).
    Parst nur so weit noetig: header -> field2 AsymmetricKeyProof -> field1 public_key."""
    if crx_bytes[:4] != b"Cr24":
        return None
    header_len = struct.unpack("<I", crx_bytes[8:12])[0]
    header = crx_bytes[12:12 + header_len]
    # CrxFileHeader field 2 (tag 0x12) = sha256_with_rsa proof
    i = 0
    while i < len(header):
        tag = header[i]; i += 1
        # nur length-delimited Felder erwartet
        ln = 0; shift = 0
        while True:
            b = header[i]; i += 1
            ln |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_no = tag >> 3
        data = header[i:i + ln]; i += ln
        if field_no == 2:  # AsymmetricKeyProof
            # darin field 1 (public_key)
            j = 0
            ftag = data[j]; j += 1
            fln = 0; shift = 0
            while True:
                b = data[j]; j += 1
                fln |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if (ftag >> 3) == 1:
                return extension_id(data[j:j + fln])
    return None
