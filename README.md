# TOTP Client (RFC 6238) 🔑⏱️

A Time-based One-Time Password (TOTP) generator written in pure Python, with no external libraries. It computes a 10-digit code with HMAC-SHA512 following RFC 6238 and RFC 4226, then sends it as the password of an HTTP Basic `Authorization` header.

I built this project to understand how authenticator apps work under the hood, implementing every step of the algorithm by hand instead of using a ready-made library.

## 🛠️ Technical Concepts Demonstrated
* **HMAC-SHA512:** using the standard `hmac` and `hashlib` modules, with comments explaining why HMAC is a keyed construction and not a plain hash.
* **Time Step (RFC 6238):** the Unix time is divided by 30 to obtain a window shared by client and server without exchanging anything.
* **Dynamic Truncation (RFC 4226):** the low 4 bits of the last byte choose an offset, 4 bytes are read from there, and the top bit is masked off with bitwise operations (`&`, `<<`, `|`).
* **Endianness and Sign Bit:** the 8-byte counter is encoded big-endian, and the most significant bit is cleared so the result is non-negative in every language (Python, Java, C...).
* **Modulo and Zero-Padding:** the code is cut to the required number of digits with `% 10**n`, and left-padded with zeros using `zfill`.
* **HTTP Basic Authentication:** `email:code` is Base64-encoded and sent via `urllib` (standard library only).

## ✅ Verification
The implementation produces the same codes as the official RFC 6238 test vectors for SHA-512 (Appendix B, 8 digits). You can reproduce this check without changing the code:

```python
import time
import totp_client as t

t.secret_key = "1234567890" * 6 + "1234"   # 64-byte seed from the RFC
t.required_code_length = 8

vectors = {
    59: "90693936",
    1111111109: "25091201",
    1111111111: "99943326",
    1234567890: "93441116",
    2000000000: "38618901",
    20000000000: "47863826",
}
for ts, expected in vectors.items():
    time.time = lambda ts=ts: ts
    print(ts, t.totp(), "OK" if t.totp() == expected else "FAIL")
```

## 🚀 How to Run
Requires Python 3 and nothing else.

```bash
python totp_client.py
```

The script generates the current code and sends a POST request to [httpbin.org](https://httpbin.org/post), which simply echoes the request back (including the `Authorization` header). Note that httpbin does **not** validate the code: it is only there to show the request.

To use your own values, edit these variables at the top of `totp_client.py`:
* `url`: the endpoint receiving the request
* `user_id` and `secret_key`: the user identifier and the shared secret
* `required_code_length`: number of digits of the code

> The secret in the repo is a placeholder. Never commit real secrets.

## ⚠️ Notes and Limitations
* A 10-digit code has less entropy than a "true" 10-digit one: the number extracted by the truncation has 31 bits (max 2,147,483,647), so the first digit can only be 0, 1 or 2. The standard 6 digits are not affected.
* The secret is derived from a plain string. Authenticator apps usually share it as a Base32 string.

## 🔮 Next Steps
* Turn `totp()` into a function that takes the secret, the timestamp and the number of digits as parameters, so it can be unit-tested directly.
* Add a verification function that accepts codes from the previous and next time window (to tolerate clock drift) and compares them in constant time with `hmac.compare_digest`.
* Support Base32 secrets and SHA-1/SHA-256, to be compatible with common authenticator apps.
