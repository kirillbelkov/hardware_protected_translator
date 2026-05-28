from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Iterable


PBKDF2_ITERATIONS = 50_000
KEY_SIZE = 32


DEMO_LICENSE_SIGNING_SECRET = b"coursework-demo-secret-change-me"


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(license_id: str, salt: bytes) -> bytes:
    #Создаёт ключ шифрования из идентификатора лицензии
    return hashlib.pbkdf2_hmac(
        "sha256",
        license_id.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def _keystream_blocks(key: bytes, nonce: bytes) -> Iterable[bytes]:
    counter = 0
    while True:
        counter_bytes = counter.to_bytes(8, "big")
        yield hashlib.sha256(key + nonce + counter_bytes).digest()
        counter += 1


def xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    #Простейший потоковый XOR на основе SHA-256
    result = bytearray()
    blocks = _keystream_blocks(key, nonce)

    for offset in range(0, len(data), 32):
        block = data[offset : offset + 32]
        stream_block = next(blocks)
        result.extend(bytes(a ^ b for a, b in zip(block, stream_block)))

    return bytes(result)


def encrypt_for_license(plain_data: bytes, license_id: str) -> dict:
    #Шифрует данные для конкретного идентификатора лицензии
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = derive_key(license_id, salt)
    cipher_data = xor_stream(plain_data, key, nonce)
    tag = hmac.new(key, nonce + cipher_data, hashlib.sha256).digest()

    return {
        "salt": b64encode(salt),
        "nonce": b64encode(nonce),
        "tag": b64encode(tag),
        "ciphertext": b64encode(cipher_data),
    }


def decrypt_for_license(package: dict, license_id: str) -> bytes:
    #Расшифровывает данные, если license_id подходит
    salt = b64decode(package["salt"])
    nonce = b64decode(package["nonce"])
    expected_tag = b64decode(package["tag"])
    cipher_data = b64decode(package["ciphertext"])

    key = derive_key(license_id, salt)
    actual_tag = hmac.new(key, nonce + cipher_data, hashlib.sha256).digest()

    if not hmac.compare_digest(expected_tag, actual_tag):
        raise ValueError("Неверный аппаратный ключ или повреждён защищённый файл")

    return xor_stream(cipher_data, key, nonce)


def sign_license_payload(payload: bytes) -> str:
    signature = hmac.new(DEMO_LICENSE_SIGNING_SECRET, payload, hashlib.sha256).digest()
    return b64encode(signature)


def verify_license_signature(payload: bytes, signature_b64: str) -> bool:
    actual = sign_license_payload(payload)
    return hmac.compare_digest(actual, signature_b64)
