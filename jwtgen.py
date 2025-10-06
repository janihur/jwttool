#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pathlib import Path
from typing import Dict, Any, List, Tuple

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def sign_hs256(unsigned: str, secret: str) -> str:
    mac = hmac.new(secret.encode('utf-8'), unsigned.encode('ascii'), hashlib.sha256).digest()
    return b64url(mac)


def sign_rs256(unsigned: str, key_path: str) -> str:
    """Sign using RS256 with the cryptography library (assumed present)."""
    pem = Path(key_path).read_bytes()
    key = load_pem_private_key(pem, password=None)
    if not isinstance(key, RSAPrivateKey):  # Defensive: ensure RSA key
        raise SystemExit("Provided key is not an RSA private key (needed for RS256)")
    sig = key.sign(
        unsigned.encode('ascii'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return b64url(sig)


def parse_claim_kv(value: str) -> Tuple[str, str]:
    if '=' not in value:
        raise argparse.ArgumentTypeError("--claim must be in key=value form")
    k, v = value.split('=', 1)
    if not k:
        raise argparse.ArgumentTypeError("claim key cannot be empty")
    return k, v


def parse_claim_json(value: str) -> Tuple[str, Any]:
    """Parse key=JSON where JSON may also be provided via @file.

    Examples:
      --claim-json meta='{"roles":["admin"],"active":true}'
      --claim-json perms=@perms.json   (file contains JSON document)
    """
    if '=' not in value:
        raise argparse.ArgumentTypeError("--claim-json must be in key=JSON form")
    k, raw = value.split('=', 1)
    if not k:
        raise argparse.ArgumentTypeError("claim key cannot be empty")
    if raw.startswith('@'):
        file_path = raw[1:]
        try:
            raw = Path(file_path).read_text(encoding='utf-8')
        except OSError as e:
            raise argparse.ArgumentTypeError(f"Could not read JSON file '{file_path}': {e}") from e
    try:
        return k, json.loads(raw)
    except json.JSONDecodeError as e:
        snippet = raw[:40].replace('\n', ' ')
        raise argparse.ArgumentTypeError(f"Invalid JSON for claim '{k}': {e.msg} (got: {snippet}...) ") from e


def build_header(alg: str, kid: str | None) -> Dict[str, Any]:
    h = {"typ": "JWT", "alg": alg.upper()}
    if kid:
        h["kid"] = kid
    return h


def build_payload(args: argparse.Namespace, extra: Dict[str, Any]) -> Dict[str, Any]:
    now = int(time.time())
    exp = now + args.ttl
    nbf = now - args.nbf_offset
    payload: Dict[str, Any] = {
        "sub": args.sub,
        "iat": now,
        "nbf": nbf,
        "exp": exp,
        "jti": args.jti or str(uuid.uuid4()),
    }
    if args.iss:
        payload["iss"] = args.iss
    if args.aud:
        payload["aud"] = args.aud
    if args.scope:
        # If space separated, -> array
        scopes = args.scope.split()
        payload["scope"] = scopes
    for k, v in extra.items():
        # Avoid overwriting existing keys silently
        if k in payload:
            raise SystemExit(f"Custom claim '{k}' would overwrite an existing standard claim")
        payload[k] = v
    return payload


def pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def generate_token(args: argparse.Namespace) -> str:
    alg = args.algorithm.lower()
    header = build_header(alg, args.kid)
    # Merge plain string claims and JSON claims (JSON has its own flag)
    extra_claims: Dict[str, Any] = {}
    if args.claim:
        for k, v in args.claim:
            extra_claims[k] = v
    if getattr(args, 'claim_json', None):
        for k, v in args.claim_json:
            if k in extra_claims:
                raise SystemExit(f"Custom JSON claim '{k}' would overwrite an existing claim from --claim")
            extra_claims[k] = v
    payload = build_payload(args, extra_claims)
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    unsigned = f"{b64url(header_json.encode())}.{b64url(payload_json.encode())}"
    if alg == 'hs256':
        if not args.secret:
            # Provide a friendly default but warn.
            if not args.quiet:
                print("[jwtgen] Warning: using default dev secret", file=sys.stderr)
            secret = 'dev-secret-change-me'
        else:
            secret = args.secret
        sig = sign_hs256(unsigned, secret)
    elif alg == 'rs256':
        if not args.key:
            raise SystemExit("--key required for rs256")
        sig = sign_rs256(unsigned, args.key)
    else:  # pragma: no cover
        raise SystemExit(f"Unsupported algorithm {alg}")
    return f"{unsigned}.{sig}"


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate JWT tokens (HS256 / RS256) for testing & demo.")
    # signing algorithm
    parser.add_argument('--algorithm', choices=['hs256', 'rs256'], default='rs256', help='Signing algorithm (default: rs256).')
    parser.add_argument('--secret', help='HS256 secret.')
    parser.add_argument('--key', help='Path to RSA private key (PEM) for RS256.')
    parser.add_argument('--kid', help='Key ID header (kid).')

    # standard claims
    parser.add_argument('--sub', default='demo', help='Standard Subject (sub) claim.')
    parser.add_argument('--aud', help='Standard Audience (aud) claim.')
    parser.add_argument('--iss', help='Standard Issuer (iss) claim.')
    parser.add_argument('--ttl', type=int, default=300, help='Time to Live in seconds (default: 300). Sets standard Expiration Time (exp) claim.')
    parser.add_argument('--nbf-offset', type=int, default=0, help='Subtract this many seconds from now for standard Not Before (nbf) claim (default: 0).')
    parser.add_argument('--jti', help='JWT ID (jti) claim (default: auto-generated uuid).')
    
    parser.add_argument('--scope', help='Space separated scopes -> scope array claim.')

    parser.add_argument('--claim', action='append', type=parse_claim_kv, help='Extra custom STRING claim key=value (repeatable).')
    parser.add_argument('--claim-json', action='append', type=parse_claim_json, help='Extra custom JSON claim key=JSON or key=@file.json (repeatable).')

    parser.add_argument('--print', dest='do_print', action='store_true', help='Pretty print header & payload to stderr.')
    parser.add_argument('--quiet', action='store_true', help='Suppress info messages (token only).')

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    token = generate_token(args)
    if args.do_print and not args.quiet:
        # Reconstruct header/payload for display (they are already computed above; recompute deterministically)
        header_b64, payload_b64, _ = token.split('.')
        header_json = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
        payload_json = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
        print('Header:', file=sys.stderr)
        print(pretty(header_json), file=sys.stderr)
        print('Payload:', file=sys.stderr)
        print(pretty(payload_json), file=sys.stderr)
    elif not args.quiet:
        # Minimal info line
        print(f"[jwtgen] alg={args.algorithm.lower()} ttl={args.ttl}", file=sys.stderr)
    print(token)
    return 0


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
