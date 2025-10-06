"""
Flask-based minimal Keepz payment integration demo.

This application exposes a simple checkout form. When a user submits an amount and a
contact value (email or phone), it constructs a payment order request for the
Keepz eCommerce API. The sensitive order details are encrypted using AES‑256 in
CBC mode and the AES key and IV are protected with RSA encryption, as described
in the Keepz documentation【17579421014685†L18-L45】. Only the required fields
for a payment are included. The code also writes the provided RSA keys to PEM
files so that the OpenSSL command‑line utilities can be used for encryption and
decryption. See README.md for additional details.
"""

import base64
import json
import os
import subprocess
import uuid
from flask import Flask, request, render_template

# -----------------------------------------------------------------------------
# Configuration values
#
# These identifiers and keys come from the Excel file supplied by the user.
# The integrator ID uniquely identifies the merchant within the Keepz system.
INTEGRATOR_ID: str = "b54a8a2b-f996-47d8-bd70-631398ae2f6a"

# The receiver ID corresponds to the beneficiary of the funds. It is provided
# by the Keepz representative. Without this ID the API will reject orders.
RECEIVER_ID: str = "5fecd954-9c60-42fb-9f9a-0343c347d1a4"

# According to the API documentation the receiverType must always be set to
# "BRANCH" when creating eCommerce orders【364432679730173†L52-L55】.
RECEIVER_TYPE: str = "BRANCH"

# Base URL for the Keepz eCommerce API. For production use the real environment
# https://gateway.keepz.me/ecommerce-service; for testing use the dev URL.
BASE_URL: str = "https://gateway.keepz.me/ecommerce-service"

# The following PEM strings are derived from the "Integrator Public Key" and
# "Integrator Private Key" columns in the provided spreadsheet. They are
# formatted with the appropriate headers, footers and line breaks so that
# OpenSSL can parse them. See the Excel file for the raw base64 values.
PUBLIC_KEY_PEM: str = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqmRDekxQ89hQ8aXrWG6J
rtwjel9eG3bE8Inj9Tl0w9KpGv6aEv0WLvMkyzzO650A1+X6YHcGeZAs4q3CRc7f
dPaRX42jKr/NyHalL+4sd27BTh9i+0LTotezCVwlbLQJcMAy9CAaddYPcZucevuq
Xh96tZ+14L4OF/xxns9JXtQiP5KsUwcIcDTuThpK6utzN1J4p8xwJhTCNpj/f/M4
g0EDL84jMUhtuRMMehS0kz5mQTIXRSL+T2DaijsjJpf7A1kOnximXJXU6iWX1VH0
yfs3xTiqS241KiTOQDymdzTFlvq3wkWx+hZ80RikndFk/DrC8iNuvfL+k0ZBGNX3
j63oNdwja2CRPoVt8jGmSwnG8JK4NyNpMWgbBek3pO1diC900s+BvE+1Ocq4CiCH
tyvE6ts/lBuypKXjjtJwkW2YOBqhZDPa3TMwBOBYiy6zbzey5xbURBIn+9gegMJd
Wy+an9u02nFIs/Q0+JzB1cxzXZ2voFYI2BNZtHZe8xf0RduZ5EI3ItSjaYj1aCBp
siWyGG4cReH9jwlHLeDEkDZd/1/TVErB/2waoj4hPrfVewLS/ZA2UoqDgzmQXZSR
MKdd39RjLZCnIycfxTMGkhWFUYY3Jet3VC9+Ab2QfiOJ6ErDzYNdzOI1RxcCy+OQ
1ociBccL8EV+HuAyvfLemVECAwEAAQ==
-----END PUBLIC KEY-----"""

PRIVATE_KEY_PEM: str = """-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDLaDh9A4WGf5ll
I558Wm1crO6HeNoSy/9arXWNtzWcI6W6ft0J8lkomCkgzqzxZHK5YM+o+OGz1GZN
iHt6C4l+6p+0NZETl5CHG7bfNSnGoc8V+IwNbBgZq1pQaW+JA5JXbjPuhA1yQcq2
cXrQNRC6zJ/JI+xyBKS0+hLVKytde1HBaALH5UmOldiRnPJHkjFTFNg6N/31ibJy
1Z3ncBwetomcAS2qx00AuikGmLSfSk3Cz3qdpih8jdYXLXwySRWMkPZk+f0H+y8F
CjrIKhy/tlagg+ZD2hmH/JLGsxbxbtlb89FVJCenAqD2zxiyy6GiuMEVP29fjXzx
W9pjde8wNKP9dpyl8BIcR2IYTKsyWx3zQ5JDnzSQwmlN7V/SVAagvfjNAKdjE0ln
Yv4orctTe3nvKiMXH30/8C8DvBcZb2xjs7nHgy1Ysjq4S9d02nGf+/IOoKMxmzi6
AXqRbFeVaDl0RLD0InSrjB2iLXZ4EtxpVivEG+OClKvvt+tLT/wskEflvMu7xA7A
Rd7icz/PAbdPH99SzqPVchZsIqhJ0bZPnkYrHj1sVCEWmFfZ+RnNviii/B6MxyZO
GBdENwoEjeo+xXZ2PyfTfFvF1ojOLvW7y1lWVoxKy9vvla+tjTw6h25iB9NplN9G
zaSur5zHDrELV+DooqpoBXCYoLJBrwIDAQABAoICAEb6fkO5d92gJxHw5Pv1vhXJ
zo59cHOAtgGZZ9zk4pMyqUEzxcQTymLs/eUR2a1+ZL4ldzE6b+AFrRE/H/9NiVQ9
YS9MRey1RdyvohevgH1st0uuaIjCgIJsld5bfG0uTuGtdfe0ItEM/kS9wqJm8giN
IPDaVUbQMf1pCitSnhZH0xaPSfEhJJLZ3TGqt6yb6hRYwL9IDJmizB9gRXKeX2Gk
Rs6mZp4iX89yJqDDpruy/QGOzvW2JoiYIe4ClEUj1Z4wc5p21YH0d8rlb++rKk8H
vKDUhgSFVcVrMHifw9DJ4pVAtnpkXGXd9/dH+xFhF20l1VKpyR5pzACZEdMFM0pa
whkSs2CX/t4JungDlmdUqDIMFP67OtEc0YNok1+Jy1HflZVsFwEkHxVqeQuDl815
vRay7FWft/81RZVy7s7dcz2msmkV6K2j27wHrChLaBHbombXeMg1KKPs+wOTloXH
Hh26arrW32bP5VKWwJ+XePlGtaNtS2MLVJq3qflwC3gjKA+ARP4xA9gDrzkCduKn
4aR3kWs2D7FH3kKiRodXtN8J3LyjITt2WPtinR3QBU6/EyUg+cxxka9c7Gucycdj
ueRMex/RVIAmGG/rI8bbQjTjXtYrRO+GubiCAqoXIk0hMFQNZLsYq+mskGGGzbLO
KfD3/Jdgc4y7rUIB7b6pAoIBAQDkpgkLxASOryi7sMH6HfyUOPLbNBMVv9QZ3Dn3
eJ3NmXGQC/1CB72fEr2InQJAfWSaMZFWqf3J8+xoqE9DZPjOd87s5lIbXBkVUe5a
sQup7eGqEWHT96kiqcUsjdmQf0Ar0reoGv+OoESOqfKSXsmp+it8/02DmYuV5JTd
TtwkSsZMMWmqFowMS42M4W3n4Gcgzw0b8AaByxh4Ig8afOQPjtpVGv99wttXWqdX
zsBU91413na2Snh9IONtRm7N2/bDOYIeD6q5jcd9qdUvleJ4t1wVclxQSg1alPNV
ufMxkbatCdnzKdZ4SsL8xI5S+CpN3ESrIQb0FUTO5OM+9CVFAoIBAQDjvTWdVpKt
ot6sS7U/o9LAnrG1m3235+Bn0bq7C+jfdJwZl128RJ+tJQmuKELot4QXsPuHnBBB
SlZepbdMPaSYHF07VaCLXJC1dxc2AOCMACzVDFxQjZS9jMikLLWLyHd4yLLpWbSS
0cwuphxBfeceUBquAoRgLK1RdoVmazZWaTp9WuhLeqtQFNwEhpwkTDezi4hQAwN0
Rg6NqsRkoblxjbVxVf5qPo8RE5DIgXu7/O0xsVM9B9YlZG8JkNpSoWK6Rst4ibTT
f6Jnk/7UJ4txAcFzqHkzU01gKJoI9fv7DkkzhAeB4BiZDzjGoddF3xs6DlAP202j
ZoAfUWENyfhjAoIBAQDIZyJsloysBqf8Acuyjk/QFi39pKHJoU2ksNp5pdUh3Aim
CWwbUK+JWiKXN44+uejQIPvS6sGPHWUqwcJfPoO4a1gJWUHDyzAM+Leh86VWdjIh
HoURBPPQdt5j05xKQs4a2uCvzaIJ/zy3kgsS8VNt0OAG+bmVy6GFakhzxGe8w3EU
XQbQ1lw/doUFYpwy7QNWxUMnJnR9lGXI/YkhXS+C12FT0Ir4Ti5zXPhpRMRcdEe1
jVudIJ6EhavwHhiGA/I/YAtEj9TCN5sO8CjzQTqzNXrXLVnt4UndB8pTa9zUqHNl
LMpDj3r0CgrnAtv/qpVhktr45sSycGXTtNfcWJ7FAoIBAQDQQUP3/yTed6Ocdxbl
fU/KKNRlOC18sSP6jEVvqnJndOESXeKvuSkzUj1J7zNQUBERARziY4pRykK1BmFZ
7LzJBJcVHTZUem8yIhctoRu1qqtUn5sDZpTvyP/pcaEKlGT8JLvGu+tunz9SIUCR
eyqQA7yCB3c542ESr4lJoRztZAjCfREThLeH4atY0CeU4cXGAADE+hx8hVvlnJU/
WMyV1Hppi7O9QDvf575sPEwEGkRlPrzZgIMJapBHdRjQmxgHM5n5PiQHjB3dDe7n
3smaq3pV42gB0VleZ4KEUzz71ZKG82NSFrUnsk2/BlwvXtgs/M2l0mtq0t6yxN41
l831AoIBAFrHRDN+ggQuO/YMAGMXo+YpAR/x8mpodUjZv2vnKVBoGrW2/DsECCuN
lELOXeZjND49L9fhTovHR2CMRLbX8vr9tMd9j85QMkImXjUkf8GzUMSdz4hOTwfz
iPRnGscVSta1NyWINr3p/vGk4wBtatY5rf9HBxF7L06QWBGIYTzN4hT+f0LANK+v
fTD7sWj2CHuKVpJY1iqkv8ebFI8No5lSqmO9P3WacEUb2oh+Tfwj2qEj9OXuMpmn
N6WNFc67fWxRgT0TuZyqSOCD7PxUBjW4SAABP/+KiWtF9MoDUrDsSCzGanRvAQaE
z4u98f0Sr12TQCY0aHR2ikoQe33zZyg=
-----END PRIVATE KEY-----"""

# Write the PEM key strings to files on startup. These files will be used by
# OpenSSL for encryption and decryption. If the files already exist they will
# be overwritten, ensuring that the current keys are always used.
_PUB_KEY_FILE = os.path.join(os.path.dirname(__file__), "integrator_public.pem")
_PRIV_KEY_FILE = os.path.join(os.path.dirname(__file__), "integrator_private.pem")
with open(_PUB_KEY_FILE, "w", encoding="utf-8") as _f_pub:
    _f_pub.write(PUBLIC_KEY_PEM)
with open(_PRIV_KEY_FILE, "w", encoding="utf-8") as _f_priv:
    _f_priv.write(PRIVATE_KEY_PEM)

def encrypt_payload(payload: dict) -> tuple[str, str]:
    """Encrypt the given payload for transmission to Keepz.

    The Keepz API requires that the order details (amount, receiverId, etc.) are
    encrypted using AES‑256 in CBC mode. A fresh random 256‑bit key and 128‑bit
    IV are generated for every request【17579421014685†L18-L45】. These values
    are then base64‑encoded, concatenated with a dot and encrypted using the
    integrator's RSA public key. The resulting base64‑encoded ciphertext is
    returned as the encryptedKeys value along with the base64‑encoded AES
    ciphertext for the payload.

    Args:
        payload: A dictionary containing the fields required by Keepz inside
            the encryptedData. At minimum this should include amount,
            receiverId, receiverType, integratorId and integratorOrderId.

    Returns:
        A tuple of (encryptedData_b64, encryptedKeys_b64).
    """
    # Convert payload to JSON string. Ensure separators to avoid whitespace.
    json_payload = json.dumps(payload, separators=(",", ":"))

    # Generate 256‑bit AES key and 128‑bit IV using os.urandom.
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    key_hex = aes_key.hex()
    iv_hex = iv.hex()

    # Encrypt the JSON payload with AES‑256‑CBC using OpenSSL. The -base64
    # flag instructs OpenSSL to output base64 without newlines.
    proc = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-K",
            key_hex,
            "-iv",
            iv_hex,
            "-base64",
        ],
        input=json_payload.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    encrypted_data_b64 = proc.stdout.decode("utf-8").strip()

    # Prepare encryptedKeys: base64 encode key and IV separately, join with dot
    key_b64 = base64.b64encode(aes_key).decode("utf-8")
    iv_b64 = base64.b64encode(iv).decode("utf-8")
    concat = f"{key_b64}.{iv_b64}".encode("utf-8")

    # Encrypt the concatenated secret using RSA public key via OpenSSL pkeyutl.
    proc2 = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            _PUB_KEY_FILE,
        ],
        input=concat,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    encrypted_keys_bytes = proc2.stdout
    encrypted_keys_b64 = base64.b64encode(encrypted_keys_bytes).decode("utf-8")

    return encrypted_data_b64, encrypted_keys_b64


def decrypt_response(enc_data_b64: str, enc_keys_b64: str) -> dict:
    """Decrypt a response from Keepz.

    Given the base64‑encoded encryptedData and encryptedKeys from a Keepz
    response, this function recovers the original response dictionary using
    RSA decryption followed by AES decryption【17579421014685†L59-L73】.

    Args:
        enc_data_b64: Base64‑encoded AES ciphertext returned by Keepz.
        enc_keys_b64: Base64‑encoded RSA ciphertext containing the AES key and
            IV, encoded as key_b64.iv_b64.

    Returns:
        The decrypted JSON payload as a dictionary.
    """
    # Decode the RSA‑encrypted secret from base64
    enc_keys_bytes = base64.b64decode(enc_keys_b64)
    # Use OpenSSL to decrypt with the private key
    proc = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-decrypt",
            "-inkey",
            _PRIV_KEY_FILE,
        ],
        input=enc_keys_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    decrypted_concat = proc.stdout.decode("utf-8")
    try:
        key_b64, iv_b64 = decrypted_concat.split(".")
    except ValueError:
        raise ValueError("Invalid concatenated key/iv format in decryptedKeys")
    aes_key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    # Decrypt the encryptedData using the recovered key and IV
    key_hex = aes_key.hex()
    iv_hex = iv.hex()
    proc2 = subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-K",
            key_hex,
            "-iv",
            iv_hex,
            "-base64",
        ],
        input=enc_data_b64.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    decrypted_json_str = proc2.stdout.decode("utf-8")
    return json.loads(decrypted_json_str)


def create_flask_app() -> Flask:
    """Factory function to create and configure the Flask application."""
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    def index():
        """Render the checkout form."""
        return render_template("index.html")

    @app.route("/create_order", methods=["POST"])
    def create_order():
        """Handle form submission and create a Keepz order."""
        try:
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            return "Invalid amount", 400
        contact = request.form.get("contact", "").strip()
        # Generate a unique identifier for the order in our system
        integrator_order_id = str(uuid.uuid4())

        # Prepare the payload for encryption (inside encryptedData)
        order_payload = {
            "amount": amount,
            "receiverId": RECEIVER_ID,
            "receiverType": RECEIVER_TYPE,
            "integratorId": INTEGRATOR_ID,
            "integratorOrderId": integrator_order_id,
        }
        # Encrypt the payload and keys
        encrypted_data, encrypted_keys = encrypt_payload(order_payload)

        # Build the request body for Keepz
        request_body = {
            "identifier": INTEGRATOR_ID,
            "encryptedData": encrypted_data,
            "encryptedKeys": encrypted_keys,
            "aes": True,
        }

        # Dispatch the request to Keepz. We do not catch SSL errors here; if the
        # request fails it will raise an exception and return an error message.
        try:
            import requests  # imported here to avoid hard dependency at module import time
            response = requests.post(f"{BASE_URL}/api/integrator/order", json=request_body)
        except Exception as exc:
            return f"Error connecting to Keepz: {exc}", 500

        if response.status_code != 200:
            return f"Keepz returned an error: {response.status_code} {response.text}", 500

        # Keepz returns JSON containing at least encryptedData and encryptedKeys.
        try:
            resp_json = response.json()
        except Exception:
            return f"Invalid JSON response from Keepz: {response.text}", 500

        # Decrypt the response if both encryptedData and encryptedKeys exist.
        if "encryptedData" in resp_json and "encryptedKeys" in resp_json:
            try:
                result = decrypt_response(resp_json["encryptedData"], resp_json["encryptedKeys"])
            except Exception as exc:
                result = {"error": f"Failed to decrypt response: {exc}"}
        else:
            result = resp_json

        # Render a result page that shows either the QR URL or the order details
        return render_template(
            "result.html",
            order_id=integrator_order_id,
            contact=contact,
            result=result,
        )

    @app.route("/callback", methods=["POST"])
    def callback():
        """Handle asynchronous callback from Keepz (optional)."""
        # Attempt to decrypt callback payload. If decryption fails we still
        # acknowledge the callback so that Keepz does not retry indefinitely.
        data = request.get_json(silent=True) or {}
        enc_data = data.get("encryptedData")
        enc_keys = data.get("encryptedKeys")
        if enc_data and enc_keys:
            try:
                result = decrypt_response(enc_data, enc_keys)
                # For now we simply log the result to stdout. In a real system
                # you'd update order status and perhaps send a receipt.
                print("Callback decrypted:", result)
            except Exception as exc:
                print("Failed to decrypt callback:", exc)
        return "OK"

    return app


if __name__ == "__main__":
    # Create and run the Flask application when executed directly. Running in
    # debug mode is convenient for development but should be disabled in
    # production.
    application = create_flask_app()
    application.run(host="0.0.0.0", port=8000, debug=True)