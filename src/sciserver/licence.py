"""Offline licence tokens signed with Ed25519.

A token is  sci1.<base64url(JSON payload)>.<base64url(signature)>. The vendor keeps the private key; the server only holds the public key,
so a customer cannot mint or extend a licence. Verification needs no network. Payload fields: id, customer, max_repos, issued (YYYY-MM-DD),
expires (YYYY-MM-DD). An expired licence never blocks merges: the server reports a neutral check explaining why, instead of silently failing PRs."""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PREFIX = "sci1"


class LicenceError(ValueError):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise LicenceError("licence is not valid base64") from None


@dataclass(frozen=True)
class Licence:
    id: str
    customer: str
    max_repos: int
    issued: dt.date
    expires: dt.date

    def expired(self, today: dt.date | None = None) -> bool:
        return (today or dt.date.today()) > self.expires

    def days_left(self, today: dt.date | None = None) -> int:
        return (self.expires - (today or dt.date.today())).days


def generate_keypair() -> tuple[bytes, str]:
    """(private key PEM, public key base64). Keep the PEM offline; give the public key to servers as SCI_LICENCE_PUBLIC_KEY."""
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pem, base64.b64encode(pub).decode()


def sign(private_pem: bytes, *, id: str, customer: str, max_repos: int, issued: dt.date, expires: dt.date) -> str:
    if max_repos < 1 or expires < issued or not customer.strip():
        raise LicenceError("invalid licence parameters")
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise LicenceError("the signing key must be an Ed25519 key")
    payload = json.dumps({"id": id, "customer": customer, "max_repos": max_repos, "issued": issued.isoformat(), "expires": expires.isoformat()},
                         sort_keys=True, separators=(",", ":")).encode()
    return f"{PREFIX}.{_b64e(payload)}.{_b64e(key.sign(payload))}"


def verify(token: str, public_key_b64: str) -> Licence:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenceError("not an SCI licence")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
    except (binascii.Error, ValueError):
        raise LicenceError("the configured licence public key is invalid") from None
    payload, sig = _b64d(parts[1]), _b64d(parts[2])
    try:
        pub.verify(sig, payload)  # signature first: nothing in the payload is trusted before this passes
    except InvalidSignature:
        raise LicenceError("licence signature is invalid") from None
    try:
        d = json.loads(payload)
        return Licence(str(d["id"]), str(d["customer"]), int(d["max_repos"]), dt.date.fromisoformat(d["issued"]), dt.date.fromisoformat(d["expires"]))
    except (KeyError, TypeError, ValueError):
        raise LicenceError("licence payload is malformed") from None


def main(argv: list[str] | None = None) -> int:
    """`sci-licence keygen|sign|verify` (vendor-side tool)."""
    import argparse
    import os
    import sys

    p = argparse.ArgumentParser(prog="sci-licence")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True, help="file to write the PRIVATE key to (mode 0600)")
    s = sub.add_parser("sign")
    s.add_argument("--key", required=True), s.add_argument("--customer", required=True), s.add_argument("--max-repos", type=int, required=True)
    s.add_argument("--days", type=int, required=True), s.add_argument("--id", default="")
    v = sub.add_parser("verify")
    v.add_argument("--public-key", required=True), v.add_argument("token")
    ns = p.parse_args(argv)
    try:
        if ns.cmd == "keygen":
            pem, pub = generate_keypair()
            fd = os.open(ns.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
            print(f"private key written to {ns.out} (keep it offline)\nSCI_LICENCE_PUBLIC_KEY={pub}")
        elif ns.cmd == "sign":
            today = dt.date.today()
            with open(ns.key, "rb") as fh:
                pem = fh.read()
            lid = ns.id or base64.b32encode(os.urandom(8)).decode().rstrip("=").lower()
            print(sign(pem, id=lid, customer=ns.customer, max_repos=ns.max_repos, issued=today, expires=today + dt.timedelta(days=ns.days)))
        else:
            lic = verify(ns.token, ns.public_key)
            print(f"valid: {lic.customer}, up to {lic.max_repos} repositories, expires {lic.expires} ({'EXPIRED' if lic.expired() else f'{lic.days_left()} days left'})")
        return 0
    except (LicenceError, OSError, ValueError) as e:
        print(f"sci-licence: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
