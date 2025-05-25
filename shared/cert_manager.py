# p2pshare/shared/cert_manager.py

from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

from shared.config import settings


def generate_self_signed_cert(common_name: str):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Save key and cert
    with open(settings.tls_key, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(settings.tls_cert, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[✔] Generated self-signed certificate and key.")


def ensure_certificates():
    if not settings.tls_cert.exists() or not settings.tls_key.exists():
        print("[⚠] TLS certificate or key not found. Generating new self-signed cert...")
        generate_self_signed_cert(common_name=settings.device_id)
    else:
        print("[✔] Found existing TLS certificate and key.")


if __name__ == "__main__":
    ensure_certificates()
