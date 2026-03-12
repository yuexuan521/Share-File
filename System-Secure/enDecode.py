# @Author：YueXuan
# @Date  ：2026/3/9 18:22

#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import base64
import hashlib
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# 基础配置
DES_KEY = b"8bytekey"   # DES 密钥必须为 8 字节
DES_IV = b"12345678"    # CBC 模式 IV 必须为 8 字节


# DES：字符串加解密
def des_encrypt_text(plaintext: str, key: bytes = DES_KEY, iv: bytes = DES_IV) -> str:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode("utf-8"), DES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode("utf-8")


def des_decrypt_text(ciphertext_b64: str, key: bytes = DES_KEY, iv: bytes = DES_IV) -> str:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    encrypted = base64.b64decode(ciphertext_b64.encode("utf-8"))
    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
    return decrypted.decode("utf-8")


# RSA：密钥生成、字符串加解密
def generate_rsa_keys(bits: int = 2048) -> Tuple[bytes, bytes]:
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def rsa_encrypt_text(plaintext: str, public_key_bytes: bytes) -> str:
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def rsa_decrypt_text(ciphertext_b64: str, private_key_bytes: bytes) -> str:
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(ciphertext_b64.encode("utf-8"))
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode("utf-8")


# SHA-1：字符串/文件摘要
def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def sha1_file(file_path: str) -> str:
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha1.update(chunk)
    return sha1.hexdigest()


# DES：文件加解密
def des_encrypt_file(input_path: str, output_path: str, key: bytes = DES_KEY, iv: bytes = DES_IV) -> None:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = cipher.encrypt(pad(data, DES.block_size))

    with open(output_path, "wb") as f:
        f.write(encrypted)


def des_decrypt_file(input_path: str, output_path: str, key: bytes = DES_KEY, iv: bytes = DES_IV) -> None:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    with open(input_path, "rb") as f:
        encrypted = f.read()

    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)

    with open(output_path, "wb") as f:
        f.write(decrypted)


# RSA：小文件分块加解密（方案A）
def rsa_encrypt_file_small(input_path: str, output_path: str, public_key_bytes: bytes) -> None:
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)

    # OAEP 填充下，明文块大小要小于密钥长度
    # 对 2048 位密钥，保守取 190 字节
    max_chunk_size = 190

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted_chunks = []
    for i in range(0, len(data), max_chunk_size):
        chunk = data[i:i + max_chunk_size]
        encrypted_chunks.append(cipher.encrypt(chunk))

    with open(output_path, "wb") as f:
        for chunk in encrypted_chunks:
            f.write(chunk)


def rsa_decrypt_file_small(input_path: str, output_path: str, private_key_bytes: bytes) -> None:
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)

    key_size_bytes = private_key.size_in_bytes()

    with open(input_path, "rb") as f:
        encrypted = f.read()

    decrypted_data = b""
    for i in range(0, len(encrypted), key_size_bytes):
        block = encrypted[i:i + key_size_bytes]
        decrypted_data += cipher.decrypt(block)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)


# 辅助函数
def save_key_file(file_path: str, key_data: bytes) -> None:
    with open(file_path, "wb") as f:
        f.write(key_data)


def file_equals(path1: str, path2: str) -> bool:
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        return f1.read() == f2.read()


def ensure_demo_file(file_path: str) -> None:
    path = Path(file_path)
    if not path.exists():
        content = (
            "这是一个用于密码学实验的小文件。\n"
            "内容较短，适合 RSA 方案A 分块加密演示。\n"
            "DES 用于对整个文件进行对称加密。\n"
            "SHA-1 用于计算文件摘要。\n"
        )
        path.write_text(content, encoding="utf-8")


# 主流程
def main() -> None:
    student_text = "20257038贠轩"   
    demo_file = "File.txt"

    ensure_demo_file(demo_file)

    print("=" * 60)
    print("一、字符串实验")
    print("=" * 60)
    print(f"原始字符串：{student_text}")

    # DES
    des_cipher = des_encrypt_text(student_text)
    des_plain = des_decrypt_text(des_cipher)
    print("\n[DES]")
    print("加密结果(Base64)：", des_cipher)
    print("解密结果：", des_plain)

    # RSA
    public_key, private_key = generate_rsa_keys()
    save_key_file("rsa_public.pem", public_key)
    save_key_file("rsa_private.pem", private_key)

    rsa_cipher = rsa_encrypt_text(student_text, public_key)
    rsa_plain = rsa_decrypt_text(rsa_cipher, private_key)
    print("\n[RSA]")
    print("加密结果(Base64)：", rsa_cipher)
    print("解密结果：", rsa_plain)

    # SHA-1
    text_sha1 = sha1_text(student_text)
    print("\n[SHA-1]")
    print("字符串摘要：", text_sha1)

    print("\n" + "=" * 60)
    print("二、文件实验")
    print("=" * 60)
    print(f"原始文件：{demo_file}")

    # DES 文件
    des_enc_file = "File_des.enc"
    des_dec_file = "File_des_dec.txt"
    des_encrypt_file(demo_file, des_enc_file)
    des_decrypt_file(des_enc_file, des_dec_file)

    print("\n[DES 文件加解密]")
    print("加密文件：", des_enc_file)
    print("解密文件：", des_dec_file)
    print("是否恢复一致：", file_equals(demo_file, des_dec_file))

    # RSA 小文件
    rsa_enc_file = "File_rsa.enc"
    rsa_dec_file = "File_rsa_dec.txt"
    rsa_encrypt_file_small(demo_file, rsa_enc_file, public_key)
    rsa_decrypt_file_small(rsa_enc_file, rsa_dec_file, private_key)

    print("\n[RSA 小文件分块加解密]")
    print("加密文件：", rsa_enc_file)
    print("解密文件：", rsa_dec_file)
    print("是否恢复一致：", file_equals(demo_file, rsa_dec_file))

    # SHA-1 文件摘要
    origin_sha1 = sha1_file(demo_file)
    des_dec_sha1 = sha1_file(des_dec_file)
    rsa_dec_sha1 = sha1_file(rsa_dec_file)

    print("\n[SHA-1 文件摘要]")
    print("原文件 SHA-1：      ", origin_sha1)
    print("DES 解密后 SHA-1：  ", des_dec_sha1)
    print("RSA 解密后 SHA-1：  ", rsa_dec_sha1)
    print("DES 恢复文件摘要一致：", origin_sha1 == des_dec_sha1)
    print("RSA 恢复文件摘要一致：", origin_sha1 == rsa_dec_sha1)

    print("\n实验完成。")


if __name__ == "__main__":
    main()
