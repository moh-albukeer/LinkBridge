"""
Cryptographic primitives for LinkBridge:
- Self-signed X.509 certificate & ECDSA P-256 keypair generation per device (no hardcoded shared keys)
- Certificate SHA-256 fingerprint calculation and pinning
- Ephemeral ECDH P-256 key exchange + HKDF-SHA256 + AES-256-GCM AEAD encryption (used on Bluetooth RFCOMM and application-layer verification)
- One-time pairing tokens with HMAC-SHA256 verification and short-lived session tokens
"""
import datetime
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


def compute_sha256_bytes(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(file_path: Path, chunk_size: int = 65536) -> str:
    """Stream-compute hex-encoded SHA-256 digest of a file without loading it all into memory."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class DeviceIdentity:
    device_id: str
    device_name: str
    platform: str  # "Windows" or "Android"
    cert_pem: bytes
    key_pem: bytes
    fingerprint_sha256: str

    @classmethod
    def load_or_create(
        cls,
        storage_dir: Path,
        device_name: str,
        platform: str = "Windows",
    ) -> "DeviceIdentity":
        storage_dir.mkdir(parents=True, exist_ok=True)
        cert_file = storage_dir / "device_cert.pem"
        key_file = storage_dir / "device_key.pem"
        meta_file = storage_dir / "device_id.txt"

        if cert_file.exists() and key_file.exists() and meta_file.exists():
            cert_pem = cert_file.read_bytes()
            key_pem = key_file.read_bytes()
            device_id = meta_file.read_text(encoding="utf-8").strip()
            cert = x509.load_pem_x509_certificate(cert_pem)
            fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            return cls(
                device_id=device_id,
                device_name=device_name,
                platform=platform,
                cert_pem=cert_pem,
                key_pem=key_pem,
                fingerprint_sha256=fp,
            )

        return cls.generate_new(storage_dir, device_name, platform)

    @classmethod
    def generate_new(
        cls,
        storage_dir: Path,
        device_name: str,
        platform: str = "Windows",
    ) -> "DeviceIdentity":
        """Generate a fresh ECDSA P-256 keypair and X.509 certificate (used for initial creation or certificate renewal)."""
        storage_dir.mkdir(parents=True, exist_ok=True)
        device_id = f"lb-{platform.lower()}-{secrets.token_hex(8)}"
        private_key = ec.generate_private_key(ec.SECP256R1())

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LinkBridge Local Mesh"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{device_name} ({device_id})"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        (storage_dir / "device_cert.pem").write_bytes(cert_pem)
        (storage_dir / "device_key.pem").write_bytes(key_pem)
        try:
            os.chmod(storage_dir / "device_key.pem", 0o600)
        except OSError:
            pass
        (storage_dir / "device_id.txt").write_text(device_id, encoding="utf-8")

        return cls(
            device_id=device_id,
            device_name=device_name,
            platform=platform,
            cert_pem=cert_pem,
            key_pem=key_pem,
            fingerprint_sha256=fp,
        )

    @staticmethod
    def fingerprint_from_pem(cert_or_pub_pem: bytes) -> str:
        if b"BEGIN CERTIFICATE" in cert_or_pub_pem:
            cert = x509.load_pem_x509_certificate(cert_or_pub_pem)
            return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        pub = serialization.load_pem_public_key(cert_or_pub_pem)
        der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()


class PairingManager:
    """
    Manages short-lived one-time pairing codes/tokens and cryptographic proof-of-possession
    during pairing over either Wi-Fi TLS or Bluetooth RFCOMM.
    """

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._active_pin: Optional[str] = None
        self._active_secret: Optional[bytes] = None
        self._expires_at: float = 0.0

    def generate_pairing_challenge(self) -> Tuple[str, str, float]:
        """
        Generate a 6-digit human-friendly PIN and a 128-bit pairing secret for QR/manual entry.
        Returns (pin_code, pairing_secret_hex, expires_at).
        """
        self._active_pin = f"{secrets.randbelow(900000) + 100000}"
        self._active_secret = secrets.token_bytes(16)
        self._expires_at = time.time() + self.ttl_seconds
        return self._active_pin, self._active_secret.hex(), self._expires_at

    def compute_pairing_hmac(
        self,
        pin_or_secret: str,
        initiator_device_id: str,
        initiator_fp: str,
        responder_device_id: str,
        responder_fp: str,
        nonce: str,
    ) -> str:
        """Compute HMAC-SHA256 binding both device identities and certificates to the pairing secret/PIN."""
        key = pin_or_secret.encode("utf-8")
        msg = f"{initiator_device_id}|{initiator_fp}|{responder_device_id}|{responder_fp}|{nonce}".encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def verify_pairing_request(
        self,
        provided_hmac: str,
        initiator_device_id: str,
        initiator_fp: str,
        responder_device_id: str,
        responder_fp: str,
        nonce: str,
    ) -> Tuple[bool, str]:
        """Verify incoming pairing request against active PIN or active QR secret."""
        if not self._active_pin or time.time() > self._expires_at:
            return False, "انتهت صلاحية رمز الاقتران أو لم يتم تفعيله (Pairing token expired or inactive)"

        expected_pin_hmac = self.compute_pairing_hmac(
            self._active_pin,
            initiator_device_id,
            initiator_fp,
            responder_device_id,
            responder_fp,
            nonce,
        )
        expected_secret_hmac = self.compute_pairing_hmac(
            self._active_secret.hex() if self._active_secret else "",
            initiator_device_id,
            initiator_fp,
            responder_device_id,
            responder_fp,
            nonce,
        )

        if hmac.compare_digest(provided_hmac, expected_pin_hmac) or hmac.compare_digest(
            provided_hmac, expected_secret_hmac
        ):
            # Invalidate one-time challenge immediately upon successful use
            self._active_pin = None
            self._active_secret = None
            return True, "تم التحقق من الاقتران بنجاح"

        return False, "رمز الاقتران غير صحيح أو فشل التحقق من الهوية (Invalid pairing proof)"

    def derive_ecdh_approval_link_key(
        self,
        local_ephemeral_priv: ec.EllipticCurvePrivateKey,
        peer_ephemeral_pub_pem: bytes,
        initiator_fp: str,
        responder_fp: str,
        client_nonce: str,
        server_nonce: str,
    ) -> bytes:
        """
        Derive a 256-bit persistent link key directly from the ephemeral ECDH P-256 shared secret
        and both devices' public key fingerprints when the user taps 'Approve / موافقة' on the device notification/dialog.
        Requires zero manual PIN typing while maintaining full 256-bit cryptographic key agreement.
        """
        peer_pub = serialization.load_pem_public_key(peer_ephemeral_pub_pem)
        if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
            raise ValueError("Peer public key is not EC P-256")
        shared_ecdh = local_ephemeral_priv.exchange(ec.ECDH(), peer_pub)
        salt = hashlib.sha256(
            f"{initiator_fp}:{responder_fp}:{client_nonce}:{server_nonce}".encode("utf-8")
        ).digest()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"LinkBridge-OneTapApproval-LinkKey-v2",
        ).derive(shared_ecdh)

    def derive_shared_link_key(
        self,
        pin_or_secret: str,
        initiator_fp: str,
        responder_fp: str,
    ) -> bytes:
        """Derive a 256-bit persistent link key bound to the two devices' certificate fingerprints."""
        salt = hashlib.sha256(f"{initiator_fp}:{responder_fp}".encode("utf-8")).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"LinkBridge-Paired-LinkKey-v1",
        )
        return hkdf.derive(pin_or_secret.encode("utf-8"))


@dataclass
class SessionInfo:
    session_token: str
    peer_device_id: str
    peer_fingerprint: str
    created_at: float
    expires_at: float
    transport_type: str


class SessionManager:
    """
    Manages short-lived authenticated sessions for paired devices.
    Rejects expired or unauthenticated tokens and supports instant revocation.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self._sessions: Dict[str, SessionInfo] = {}

    def create_session(
        self,
        peer_device_id: str,
        peer_fingerprint: str,
        transport_type: str,
    ) -> SessionInfo:
        now = time.time()
        token = secrets.token_urlsafe(32)
        info = SessionInfo(
            session_token=token,
            peer_device_id=peer_device_id,
            peer_fingerprint=peer_fingerprint,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            transport_type=transport_type,
        )
        self._sessions[token] = info
        return info

    def validate_session(
        self,
        session_token: str,
        expected_device_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[SessionInfo], str]:
        info = self._sessions.get(session_token)
        if not info:
            return False, None, "جلسة غير مصادق عليها أو غير موجودة (Unauthorized session)"
        if time.time() > info.expires_at:
            del self._sessions[session_token]
            return False, None, "انتهت صلاحية الجلسة، يرجى إعادة الاتصال (Session expired)"
        if expected_device_id and info.peer_device_id != expected_device_id:
            return False, None, "تعارض في هوية الجهاز المقترن (Device identity mismatch)"
        return True, info, "OK"

    def revoke_device_sessions(self, peer_device_id: str) -> int:
        to_remove = [k for k, v in self._sessions.items() if v.peer_device_id == peer_device_id]
        for k in to_remove:
            del self._sessions[k]
        return len(to_remove)

    def revoke_all(self) -> None:
        self._sessions.clear()


class AeadChannelCipher:
    """
    Provides application-layer authenticated encryption (ECDH P-256 + HKDF-SHA256 + AES-256-GCM)
    with monotonic sequence numbers for transports that lack TLS (specifically Bluetooth RFCOMM).
    Never uses custom cryptography — relies strictly on standard NIST P-256 ECDH, HKDF, and AES-256-GCM.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        self._aesgcm = AESGCM(key)
        self._send_seq = 0
        self._recv_seq = 0

    @staticmethod
    def generate_ephemeral_ecdh() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub_bytes

    @classmethod
    def from_ecdh_and_link_key(
        cls,
        local_ephemeral_priv: ec.EllipticCurvePrivateKey,
        peer_ephemeral_pub_pem: bytes,
        paired_link_key: bytes,
        context_transcript: bytes,
    ) -> "AeadChannelCipher":
        peer_pub = serialization.load_pem_public_key(peer_ephemeral_pub_pem)
        if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
            raise ValueError("Peer public key is not EC")
        shared_ecdh = local_ephemeral_priv.exchange(ec.ECDH(), peer_pub)
        # Combine forward-secret ECDH shared secret with the paired link key via HKDF-SHA256
        salt = hashlib.sha256(paired_link_key + context_transcript).digest()
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"LinkBridge-RFCOMM-AES256GCM-v1",
        ).derive(shared_ecdh)
        return cls(session_key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        nonce = self._send_seq.to_bytes(12, byteorder="big")
        self._send_seq += 1
        ct = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ct

    def decrypt(self, payload: bytes, associated_data: bytes = b"") -> bytes:
        if len(payload) < 28:  # 12-byte nonce + 16-byte GCM tag
            raise ValueError("Truncated AEAD ciphertext")
        nonce = payload[:12]
        seq = int.from_bytes(nonce, byteorder="big")
        if seq < self._recv_seq:
            raise ValueError(f"Replay detected on AEAD channel: seq {seq} < expected {self._recv_seq}")
        self._recv_seq = seq + 1
        ct = payload[12:]
        return self._aesgcm.decrypt(nonce, ct, associated_data)
