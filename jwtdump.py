#!/usr/bin/env python3

from __future__ import annotations

import sys, json, base64, argparse, hmac, hashlib

from typing import Tuple
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

def b64url_decode(segment: str) -> bytes:
    pad = '=' * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except Exception as e:
        raise ValueError(f"Invalid base64 segment: {segment[:15]}...") from e


def split_jwt(token: str) -> Tuple[str, str, str | None]:
    parts = token.strip().split('.')
    if len(parts) == 2:
        return parts[0], parts[1], None
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    raise ValueError("Token must have 2 or 3 dot-separated parts")


def pretty(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def verify_hs256(unsigned: str, sig_b64: str, secret: str) -> bool:
    mac = hmac.new(secret.encode(), unsigned.encode('ascii'), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(mac).decode().rstrip('=')
    return hmac.compare_digest(expected, sig_b64)


def verify_rs256(unsigned: str, sig_b64: str, key: RSAPublicKey) -> bool:
    """Verify RS256 signature using provided RSA public key PEM.

    Returns True if signature verifies, False otherwise.
    """
    try:
        sig = b64url_decode(sig_b64)
        key.verify(
            sig,
            unsigned.encode('ascii'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show JWT header & payload and optionally verify signature.")
    parser.add_argument("token", help="JWT string or '-' to read from stdin.")
    parser.add_argument("--secret", help="HS256 secret to (optionally) verify signature")
    def rsa_public_key(path: str) -> RSAPublicKey:
        try:
            data = Path(path).read_bytes()
            key = load_pem_public_key(data)
        except Exception as e:
            raise argparse.ArgumentTypeError(f"Invalid RSA public key file '{path}': {e}")
        if not isinstance(key, RSAPublicKey):
            raise argparse.ArgumentTypeError("Provided key is not an RSA public key")
        return key
    parser.add_argument(
        "--key",
        type=rsa_public_key,
        help="Path to RSA public key PEM for (optional) RS256 verification."
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    token = sys.stdin.read().strip() if args.token == '-' else args.token.strip()
    try:
        h_b64, p_b64, s_b64 = split_jwt(token)
        header = json.loads(b64url_decode(h_b64) or b"{}")
        payload = json.loads(b64url_decode(p_b64) or b"{}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print("Header:")
    print(pretty(header))
    print("\nPayload:")
    print(pretty(payload))

    if s_b64 is not None:
        print("\nSignature (raw base64url):")
        print(s_b64)
        alg = header.get("alg", "").upper()
        unsigned = f"{h_b64}.{p_b64}"
        if args.secret and alg == "HS256":
            ok = verify_hs256(unsigned, s_b64, args.secret)
            print(f"\nHS256 verification: {'OK' if ok else 'FAIL'}")
        if args.key and alg == "RS256":
            ok = verify_rs256(unsigned, s_b64, args.key)
            print(f"\nRS256 verification: {'OK' if ok else 'FAIL'}")
    else:
        print("\n(No signature part present)")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))