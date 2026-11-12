# TOTP (RFC 6238) client built from scratch with HMAC-SHA512 (no external libraries).
# It generates a 10-digit time-based one-time password and sends it as the password of an HTTP Basic Authorization header.
# The demo endpoint (httpbin) only echoes the request back: it does not validate the code.
import json
import time
import hmac
import hashlib
import math
import urllib.request
import urllib.error
import base64

url = "https://httpbin.org/post"
data = {
    "message": "TOTP demo",
    "solution_language": "python"
}

user_id = "user@example.com"
# In this demo the shared secret is derived from the user ID plus a fixed suffix. In a real system it would be
# a random value generated per user and stored securely (usually shared with the user as a Base32 string).
secret_key = user_id + "SHARED_SECRET_SUFFIX"
# The password must be an RFC 6238 TOTP code, 10 digits long
required_code_length = 10

def generate_hmac_sha512(key: bytes, message: bytes):
    # Create an HMAC object from the key and the message, using SHA-512 as the underlying hash.
    # HMAC stands for "Keyed-Hash Message Authentication Code";
    # HMAC is not a hash algorithm in its own right, but a construction (a standardized recipe, RFC 2104)
    # that takes an existing hash algorithm (such as SHA-512, SHA-256, but also MD5)
    # and turns it into an authentication tool using a secret key.
    # In fact, SHA-512 alone only takes the message: anyone can recompute it, so it can only detect
    # accidental changes (integrity). HMAC-SHA-512 also requires a [secret] key, so only
    # those who know the key can calculate (or verify) the output. This allows verifying the sender's authenticity as well.
    # In other words, SHA-512 is a mere hash function, while HMAC-SHA-512 is an
    # authentication mechanism, as mentioned above.
    hmac_object = hmac.new(key, message, hashlib.sha512)

    # In the case of HMAC-SHA-512, the output's length in bits is 512,
    # in bytes it's 512 / 8 = 64, while in characters (if represented as a hexstring) it is 128 chars long.
    # Starting from the output alone, it's basically impossible to get either the original message
    # or the secret key.
    # Even a minimal change to either the original message or the key yields a completely different output.
    # In this case, we want the HMAC output value to be represented as bytes, hence the use of "digest()"
    # The method ".hexdigest()" would have returned the 128-character hex string we mentioned above.
    return hmac_object.digest()
    # Either way, the result can be called in different ways:
    # - "(HMAC) tag", as it's usually referred to in cryptographic specifications (e.g., RFC);
    # - "MAC" (which stands for "Message Authentication Code"), which is a generic name;
    # - "(HMAC) signature", which is the name commonly used in everyday code (e.g., HTTP request signing).
    #   This is the one that will be used in this program.

def totp():
    # Unix time (seconds since 1970-01-01 00:00:00 UTC) divided by 30 (integer division) to have a "30 s window".
    # This is the "time step" of RFC 6238 (X = 30, with start time T0 = 0): all the codes generated within the same
    # 30 seconds are identical, so client and server can agree on the code without exchanging anything.
    time_window = math.floor(time.time() / 30)

    # Generate HMAC-SHA512 signature
    # It requires the secret key and the time window (the moving factor).
    # HMAC accepts these two only in the format of bytes (so string and integer are not valid).
    # For this reason, both are converted. Specifically:
    # - The secret key is converted from string to bytes through the "encode()" method;
    # - The time window is converted from integer to bytes through the "to_bytes" method, which:
    #   - takes the integer parameter "length", which refers to the length in bytes of the resulting bytes object;
    #   - takes the parameter "byteorder", which can be set either to "big" or "little", depending on whether
    #     the representation is required in the big-endian or little-endian system (the HOTP/TOTP RFCs require
    #     the counter as an 8-byte "big" value)
    signature = generate_hmac_sha512(secret_key.encode("utf-8"), time_window.to_bytes(8, "big"))

    # The signature has to be truncated, since we only need 10 digits out of the 128 hex characters (64 bytes).
    # This step is the dynamic truncation (defined in RFC 4226, on which TOTP is built): the 4 low-order (least significant)
    # bits of the last byte choose where to start reading, you read 4 bytes from there, you clear the top bit,
    # you take the modulo 10^digits and you left-pad with zeros. With 10 digits you'll notice an oddity: the extracted
    # number is a 31-bit one, so at most about 2.1 billion, and the result will often have a leading zero. This is normal.

    # Extract the last byte
    last_byte = signature[len(signature) - 1] # or signature[-1] to start from the end of the list instead of from the beginning
    # Extract the four least significant ("low") bits (called nibble) of the extracted byte.
    # To isolate the lower 4 bits of a byte while clearing out the upper 4 bits,
    # a 0x0F mask is used (0x0F is a hexadecimal value equal to 15 in decimal or 0000 1111 in binary),
    # in a bitwise operation. In our case, the bitwise operation is AND (&). This works because "&"
    # doesn't compare the whole number represented, but rather single bits. Since the 4 most significant
    # bits of 0x0F are 0s and since the AND operator only returns 1 when both bits compared are 1, the
    # resulting 4 most significant bits will equal 0, so they'll be irrelevant at this point. On the other
    # hand, the least significant bits of 0x0F are 1s, so the least significant bits of the original byte
    # will not be affected: zeros will remain zeros and ones will remain ones.
    start_offset = last_byte & 0x0F

    # At this point, we have a number from 0 to 15 that indicates from which byte in the signature to start
    # reading 4 bytes, so we extract those 4 bytes. These bytes are the pieces that make up a
    # single large pseudo-random number, extracted directly from the "heart" of our HMAC signature.
    # (Since the signature is 64 bytes long, reading up to offset 15 + 3 = 18 is always safe.)
    # The breakdown of these 4 bytes is as follows (as an example, we'll pretend that start_offset contains "5"):
    # - byte 5 (The "Head"): this represents the most significant part of the number. Its most significant bit
    # is removed (using & 0x7F) solely to ensure that the final number is always positive and does not cause
    # sign errors in various programming languages (see below);
    # - bytes 6 and 7 (the "Body"): these are the intermediate bytes that add precision and randomness to the value;
    # - byte 8 (the "Tail"): this is the least significant byte, which shifts the final value by one unit at a time.

    # Before extracting, another concept.
    # As mentioned above, the most significant bit of the extracted number (here called "hmac_4bytes") must be "removed" (set to 0).
    # This matters mostly for implementations in languages that use signed 32-bit integers, because of the two's complement
    # representation. Python itself wouldn't strictly need it (its integers have arbitrary precision), but the code has to match
    # what every other implementation computes. The 4 bytes we extracted correspond to 32 bits. To assign a sign (+ / -) to binary
    # numbers, the most significant bit is used to store that sign (0 equals to +, 1 equals to -). For example, if we have the
    # number "+1", in 32-bit binary code, it would be: 00000000 00000000 00000000 00000001. In order to represent -1, we:
    # - mechanically invert all digits ("NOT" operation -> 11111111 11111111 11111111 11111110);
    # - add 1 -> 11111111 11111111 11111111 11111111 (which, in two's complement representation, stands for "-1").
    # In the first byte, it matters whether the most significant bit is 1 or 0 because of the final mathematical operation:
    # the modulo calculation (% 10^digits). If the first bit on the left were 1 and the calculation were carried out by a Java server
    # (which reads the 32 bits as a signed number), Java would interpret that block of memory as a negative number (e.g. -1,234,567,890).
    # When you try to calculate the remainder of a division involving a negative number (e.g. -1234567890 % 1000000), different languages
    # produce different results:
    # - Python returns a positive remainder (the result takes the sign of the divisor);
    # - Java and C return a negative remainder (the result takes the sign of the dividend);
    # In C (32 bit), the number -1 in memory is a block of 32 bits: 11111111 11111111 11111111 11111111.
    # In Python, instead, integers have no fixed number of bits: for bitwise operations, a negative number behaves as if it had
    # infinitely many 1s on the left (...11111111 11111111 11111111 11111111), which guarantees arbitrary precision (internally,
    # an integer is a variable-length array of digits with a separate sign). A Python integer NEVER overflows.
    # In any case, this mismatch would break compatibility, so the HOTP RFC (on which TOTP is built) solves the problem at its root
    # with a drastic rule: the first bit is always forced to 0 (sacrificing 1 bit of entropy). This way, the number is guaranteed to be
    # positive in any programming language, and the modulo operation always yields the exact same n-digit code for everyone.
    # Now, there are mainly two approaches to "get rid" of the most significant bit:
    # - set the most significant bit to zero before shifting the first byte: (signature[offset] & 0x7F) << 24
    # - first combine all four bytes, then apply the huge mask "& 0x7FFFFFFF" for the same exact result: hmac_4bytes & 0x7FFFFFFF
    # Regarding the three masks used here:
    # - 0x7F (hexadecimal for 127) acts on a single byte (8 bits). In binary it's 0111 1111. We use it for the first byte.
    # - 0xFF (hexadecimal for 255) also acts on a single byte (8 bits). In binary it's 1111 1111. We use it for the second, third
    #   and fourth byte (see below)
    # - 0x7FFFFFFF (hexadecimal for 2,147,483,647) acts on 4 bytes (32 bits). In binary it's 01111111 11111111 11111111 11111111.
    #   We use it for the 4 bytes "together" (alternative approach below)
    # The "<<" is the shift operator, and it's used to move bits to the left. It fills empty positions on the right with 0s. For example,
    # for the first byte below, we take the first byte (signature[start_offset]), we set its most significant bit to 0 (& 0x7F) and
    # then we shift it to the left by 24 bits (so we add 24 bits on its right): (ex.) 10101010 -> 00101010 -> 00101010 00000000 00000000 00000000.
    # So now we've got our "head". For the second byte, we shift it by 16 bits. So if the second byte is, say, 10001101,
    # it becomes 10001101 00000000 00000000. The third byte is shifted by 8 bits (ex. 00011010 -> 00011010 00000000) and the fourth is not
    # shifted at all (ex. 00000001). All 4 results are passed through the bitwise OR operator (|), which joins them together.

    # Regarding the "0xFF" mask applied to the second, third and fourth byte, there is an important detail:
    # In plain Python, if you're extracting from a bytes object, it's technically redundant, because Python already returns
    # a value guaranteed to be between 0 and 255. However, when implementing cryptographic algorithms, "& 0xFF" is almost always
    # included as defensive programming (it's a habit that comes directly from C). If for some reason
    # the source array contained signed integers (e.g., -128 to 127 instead of 0 to 255), without "& 0xFF" Python would extend
    # the negative sign with infinitely many 1s on the left. When you then OR (|) the pieces together, those 1s would overwrite
    # and destroy the adjacent bytes. "& 0xFF" acts as a physical barrier that says: "whatever this number is, cut everything off
    # and keep only the last 8 bits".

    hmac_4bytes = (
        (signature[start_offset] & 0x7F) << 24 |
        (signature[start_offset + 1] & 0xFF) << 16 |
        (signature[start_offset + 2] & 0xFF) << 8 |
        (signature[start_offset + 3] & 0xFF)
    )
    # Alternative:
    # hmac_4bytes = int.from_bytes(signature[start_offset:start_offset + 4], "big") & 0x7FFFFFFF

    # The next operation is the truncation. We'll use the modulo operator % and 10 to the power of the number of digits we want the code to be
    # made of (also 10, in this case). The modulo isn't used to "get 10 digits", but it exploits powers of 10 (like 10^6 or 10^8)
    # to extract the desired code length, which by convention is almost always 6 digits (e.g., Google Authenticator).
    # The 31-bit number we just assembled (for example, 713890305) is too long, hard to memorize
    # at a glance and inconvenient to type quickly on a keyboard. The purpose of an authenticator app is to give you a compact PIN.
    # In mathematics, taking the modulo (%) of a number by a power of 10 is the quickest trick to "cut off" the left part
    # of a decimal number and keep only the last X digits on the right. Let's take our integer 713890305:
    # - If the service requires the classic 6-digit code, take the modulo by 10^6 (1,000,000): 713890305 % 1000000 = 890305. That's your TOTP code.
    # - If a stricter service requires an 8-digit code, take the modulo by 10^8 (100,000,000): 713890305 % 100000000 = 13890305.
    # In our case, we want 10 digits, so 10^10 = a whopping 10 billion (10,000,000,000)! That's well above the largest value our number
    # can have (2^31 - 1 = 2,147,483,647), so in the context of this program it's completely redundant, but we include it for the sake of
    # generality. (Side effect: a 10-digit code obtained this way has less entropy than a "true" 10-digit code, since its first digit can only be 0, 1 or 2.)
    code = hmac_4bytes % 10**required_code_length
    code = str(code)

    # Since "hmac_4bytes" is an integer, it can't keep leading zeros: if the number has fewer than 10 digits (e.g., 123456789),
    # the string will be shorter than 10 characters, and it may cause errors. So we convert it to string (above) and we fill the left
    # of the string with 0s where necessary (below)
    code = code.zfill(required_code_length)

    return code

def main():
    # Calculate password
    password = totp()

    # Merge user_id and calculated password (separated by a colon)
    credentials = f"{user_id}:{password}"

    # Credentials have to be encoded before using them as authorisation header,
    # for the request. The authorisation has this format: "Basic <base64 of "email:password">".
    # Encoding consists of the following steps:
    # - convert credentials to bytes (encode())
    # - encode result in base64 (base64.b64encode(...))
    # - decode back to string
    # Then add "Basic " to the beginning of the string
    # (Note that Base64 is just an encoding, not encryption: the connection must be protected by HTTPS)
    credentials_encoded = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

    # Convert dictionary to a JSON string and encode to bytes
    json_bytes = json.dumps(data).encode("utf-8")

    # Create the Request object and specify headers
    post_request = urllib.request.Request(
        url,
        data = json_bytes,
        headers = {
            "Authorization": credentials_encoded,
            "Content-Type": "application/json"
        }
    )

    # Send the request and handle the response
    # NOTE: In urllib, simply passing the data bytes argument to urllib.request.Request
    # automatically switches the HTTP method from GET to POST.
    try:
        with urllib.request.urlopen(post_request) as response:
            # Read and decode the response body
            response_body = response.read().decode("utf-8")
            response_data = json.loads(response_body)
            print("Status Code:", response.getcode())
            print("Response:", response_data)
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")

if __name__ == "__main__":
    main()
