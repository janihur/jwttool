# JWT Command Line Encoding and Decoding Tool

This is not a "full-featured" JWT tool but does what I needed for testing purposes:
* `jwtgen.py`: JWT token encoding (generation) tool
* `jwtdump.py`: JWT token decoding tool

90% of the code has been generated with AI agent. Later I realised that e.g. [PyJWT](https://pypi.org/project/PyJWT/) exists but this implementation already did what I needed so I stuck with it.

## RS256 Key Generation

RS256 signing algorithm key generation:
```
openssl genrsa -out private-key.pem 4096
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

Key identifier (kid) generation:
```
KID=$(openssl rsa -in private-key.pem -pubout -outform DER \
  | openssl sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=')
echo "$KID"
```

## Development Notes

Uses virtual environment to manage dependencies:
* [cryptography](https://pypi.org/project/cryptography/)

Create virtual environment:
```
python3 -m venv .venv
```

Activate virtual environment:
```
source .venv/bin/activate
```

Install dependencies into virtual environment (the first time):
```
pip install cryptography
```

Install dependencies into virtual environment (subsequent times):
```
pip install -r requirements.txt
```

Freeze dependencies:
```
pip freeze > requirements.txt
```

Deactivate virtual environment:
```
deactivate
```