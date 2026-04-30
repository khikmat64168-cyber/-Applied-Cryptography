"""
응용암호연구 중간고사 프로젝트 과제
Diffie-Hellman 키 합의 + AES-256-CBC 암호화 시뮬레이션
"""

import random
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─── RFC 3526: 1024-bit MODP 그룹 (표준 안전 소수) ───────────────────────────
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)
G = 2  # 생성원 (primitive root mod P)


# ─── DH 키 합의 ────────────────────────────────────────────────────────────────

def dh_step1_public_params():
    """공개 매개변수 출력"""
    print("=" * 65)
    print("  Diffie-Hellman 키 합의 + AES-256-CBC 암호화 시뮬레이션")
    print("=" * 65)
    print("\n[1단계] 공개 매개변수 설정 (RFC 3526 1024-bit MODP 그룹)")
    print(f"  p (안전 소수, 1024-bit): {hex(P)[:18]}...{hex(P)[-6:]}")
    print(f"  g (생성원): {G}")


def dh_step2_keygen():
    """Alice(송신자)와 Khikmat(수신자) 각자 개인키/공개키 생성"""
    a = random.randint(2, P - 2)   # Alice 개인키
    A = pow(G, a, P)               # Alice 공개키: A = g^a mod p

    b = random.randint(2, P - 2)   # Khikmat 개인키
    B = pow(G, b, P)               # Khikmat 공개키:   B = g^b mod p

    print("\n[2단계] 개인키 / 공개키 생성")
    print(f"  [Alice   - 송신자]")
    print(f"    개인키 a       : {hex(a)[:18]}...")
    print(f"    공개키 A=g^a%p : {hex(A)[:18]}...")
    print(f"  [Khikmat - 수신자]")
    print(f"    개인키 b       : {hex(b)[:18]}...")
    print(f"    공개키 B=g^b%p : {hex(B)[:18]}...")

    return a, A, b, B


def dh_step3_shared_secret(a, A, b, B):
    """공개키 교환 후 각자 공유 비밀키 계산"""
    # Alice가 Khikmat의 공개키로 계산
    alice_shared   = pow(B, a, P)   # K = B^a mod p = g^(ab) mod p
    # Khikmat이 Alice의 공개키로 계산
    khikmat_shared = pow(A, b, P)   # K = A^b mod p = g^(ab) mod p

    print("\n[3단계] 공개키 교환 및 공유 비밀키 계산")
    print(f"  Alice  : K = B^a mod p = {hex(alice_shared)[:18]}...")
    print(f"  Khikmat: K = A^b mod p = {hex(khikmat_shared)[:18]}...")

    assert alice_shared == khikmat_shared, "키 합의 실패: 두 값이 다름!"
    print(f"  ✓ 키 합의 성공 — 두 공유 비밀키가 일치합니다.")
    return alice_shared  # == khikmat_shared


# ─── AES 키 유도 ───────────────────────────────────────────────────────────────

def derive_aes_key(shared_secret: int) -> bytes:
    """공유 비밀키 → SHA-256 → 256-bit AES 키"""
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, "big"
    )
    aes_key = hashlib.sha256(secret_bytes).digest()
    print("\n[4단계] AES 키 유도 (SHA-256 해시)")
    print(f"  AES-256 키 (32 bytes): {aes_key.hex()}")
    return aes_key


# ─── AES-256-CBC 암호화 / 복호화 ───────────────────────────────────────────────

def pkcs7_pad(data: bytes, block=16) -> bytes:
    pad_len = block - len(data) % block
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt(message: str, aes_key: bytes):
    iv = os.urandom(16)  # 랜덤 초기 벡터
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(message.encode("utf-8"))
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    print("\n[5단계] 송신자(Alice) → 메시지 AES-256-CBC 암호화")
    print(f"  원본 메시지 : {message}")
    print(f"  IV          : {iv.hex()}")
    print(f"  암호문      : {ciphertext.hex()}")
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, aes_key: bytes) -> str:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = pkcs7_unpad(padded).decode("utf-8")

    print("\n[6단계] 수신자(Khikmat) → 암호문 복호화")
    print(f"  복호화된 메시지: {plaintext}")
    return plaintext


# ─── 메인 시뮬레이션 ───────────────────────────────────────────────────────────

def main():
    dh_step1_public_params()

    a, A, b, B = dh_step2_keygen()
    shared_secret = dh_step3_shared_secret(a, A, b, B)
    aes_key = derive_aes_key(shared_secret)

    message = "안녕하세요 Khikmat! 이 메시지는 DH 키 합의로 공유된 비밀키로 암호화되었습니다."
    iv, ciphertext = aes_encrypt(message, aes_key)
    recovered = aes_decrypt(iv, ciphertext, aes_key)

    print("\n" + "=" * 65)
    ok = "✓ 성공" if recovered == message else "✗ 실패"
    print(f"  시뮬레이션 결과: {ok} — 원본 메시지와 복호화 메시지 일치")
    print("=" * 65)


if __name__ == "__main__":
    main()
