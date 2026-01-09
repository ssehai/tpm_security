#!/usr/bin/env python3
import os
import sys
import json
import base64
import getpass
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------- 공용 유틸 ----------

def run_cmd(args, input_bytes=None):
    """
    tpm2-tools용 subprocess 래퍼.
    에러 발생 시 예외 발생.
    """
    result = subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(args)}\n"
            f"stdout: {result.stdout.decode(errors='ignore')}\n"
            f"stderr: {result.stderr.decode(errors='ignore')}"
        )
    return result.stdout


def ensure_primary(primary_ctx="primary.ctx"):
    if Path(primary_ctx).exists():
        return
    print("[*] Creating primary key (owner hierarchy)...")
    run_cmd(["tpm2_createprimary", "-C", "o", "-c", primary_ctx])


# ---------- TPM 관련 함수 (auth-only) ----------

def tpm_get_random(num_bytes=32):
    print(f"[*] Getting {num_bytes} random bytes from TPM...")
    return run_cmd(["tpm2_getrandom", str(num_bytes)])


def tpm_seal_key(key_bytes: bytes, key_name: str, obj_auth: str, primary_ctx="primary.ctx"):
    """
    authValue(비밀번호)로 sealed object 생성
    -> key_name.pub, key_name.priv 생성
    """
    ensure_primary(primary_ctx)

    tmp_key_file = f"{key_name}.key.bin"
    with open(tmp_key_file, "wb") as f:
        f.write(key_bytes)

    print(f"[*] Sealing AES key into TPM (key_name={key_name}) with auth only...")
    run_cmd([
        "tpm2_create",
        "-C", primary_ctx,
        "-u", f"{key_name}.pub",
        "-r", f"{key_name}.priv",
        "-i", tmp_key_file,
        "-p", f"str:{obj_auth}",
        "-a", "fixedtpm|fixedparent|userwithauth",
    ])

    os.remove(tmp_key_file)
    print("[*] Sealed key files generated:", f"{key_name}.pub", f"{key_name}.priv")


def tpm_unseal_key(key_name: str, obj_auth: str, primary_ctx="primary.ctx") -> bytes:
    """
    key_name.pub/priv를 load 후 auth로 unseal
    """
    ensure_primary(primary_ctx)

    pub = Path(f"{key_name}.pub")
    priv = Path(f"{key_name}.priv")
    if not (pub.exists() and priv.exists()):
        raise FileNotFoundError(f"Sealed key files not found: {pub}, {priv}")

    ctx_file = f"{key_name}.ctx"
    print(f"[*] Loading sealed key object (key_name={key_name})...")
    run_cmd([
        "tpm2_load",
        "-C", primary_ctx,
        "-u", str(pub),
        "-r", str(priv),
        "-c", ctx_file,
    ])

    try:
        print("[*] Unsealing key from TPM with auth only...")
        key_bytes = run_cmd([
            "tpm2_unseal",
            "-c", ctx_file,
            "-p", f"str:{obj_auth}",
        ])
    finally:
        try:
            run_cmd(["tpm2_flushcontext", "-c", ctx_file])
        except Exception:
            pass
        try:
            os.remove(ctx_file)
        except Exception:
            pass

    if len(key_bytes) != 32:
        raise RuntimeError(f"Unexpected key length from TPM: {len(key_bytes)} bytes")
    return key_bytes


# ---------- AES-GCM 스트리밍 암/복호화 ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def get_obj_auth():
    auth = os.environ.get("TPM_OBJECT_AUTH")
    if auth:
        return auth
    return getpass.getpass("TPM object auth (will not echo): ")


def encrypt_file_stream(
    input_path: str,
    out_enc_path: str,
    out_meta_path: str,
    key_name: str,
    aad: bytes | None = None,
    chunk_size: int = 4 * 1024 * 1024,  # 4MB
):
    """
    - input_path: 평문 파일
    - out_enc_path: 암호문 바이너리 (*.enc)
    - out_meta_path: 메타데이터 JSON (*.meta.json)
    - key_name: TPM sealed key prefix (key_name.pub/priv 생성)
    """
    input_path = Path(input_path)
    out_enc_path = Path(out_enc_path)
    out_meta_path = Path(out_meta_path)

    obj_auth = get_obj_auth()

    # 1) TPM RNG로 AES-256 키 생성
    key = tpm_get_random(32)
    if len(key) != 32:
        raise RuntimeError(f"TPM random length != 32: {len(key)}")

    # 2) Nonce 생성 (GCM 권장 96-bit)
    nonce = os.urandom(12)

    # 3) GCM encryptor 준비 (스트리밍)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
    ).encryptor()

    if aad is not None:
        encryptor.authenticate_additional_data(aad)

    # 4) 스트리밍 암호화: plaintext -> ciphertext
    print(f"[*] Streaming encrypt: {input_path} -> {out_enc_path}")
    total_in = 0
    total_out = 0

    with input_path.open("rb") as fin, out_enc_path.open("wb") as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            total_in += len(chunk)
            c = encryptor.update(chunk)
            if c:
                fout.write(c)
                total_out += len(c)

        # finalize() 호출 후 tag 확정
        tail = encryptor.finalize()
        if tail:
            fout.write(tail)
            total_out += len(tail)

    tag = encryptor.tag

    # 5) meta.json 기록 (작게)
    meta = {
        "version": 1,
        "cipher": "AES-256-GCM",
        "key_name": key_name,
        "sealed_pub": f"{key_name}.pub",
        "sealed_priv": f"{key_name}.priv",
        "nonce_b64": b64e(nonce),
        "tag_b64": b64e(tag),
        "aad_b64": None if aad is None else b64e(aad),
        "chunk_size": chunk_size,
        "plaintext_bytes": total_in,
        "ciphertext_bytes": total_out,
    }
    out_meta_path.write_text(json.dumps(meta, indent=2))
    print(f"[*] Wrote meta: {out_meta_path}")

    # 6) 키를 TPM에 seal (auth-only)
    tpm_seal_key(key, key_name, obj_auth=obj_auth)
    print("[*] Encryption + TPM seal completed.")


def decrypt_file_stream(
    in_enc_path: str,
    in_meta_path: str,
    output_path: str,
    chunk_size: int | None = None,
):
    """
    - in_enc_path: 암호문 바이너리 (*.enc)
    - in_meta_path: 메타데이터 JSON (*.meta.json)
    - output_path: 복호화 평문 파일
    """
    in_enc_path = Path(in_enc_path)
    in_meta_path = Path(in_meta_path)
    output_path = Path(output_path)

    meta = json.loads(in_meta_path.read_text())

    key_name = meta["key_name"]
    nonce = b64d(meta["nonce_b64"])
    tag = b64d(meta["tag_b64"])
    aad_b64 = meta.get("aad_b64")
    aad = None if aad_b64 is None else b64d(aad_b64)

    if chunk_size is None:
        chunk_size = int(meta.get("chunk_size", 4 * 1024 * 1024))

    obj_auth = get_obj_auth()

    # 1) TPM에서 키 unseal
    key = tpm_unseal_key(key_name, obj_auth=obj_auth)

    # 2) GCM decryptor 준비 (tag 포함)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
    ).decryptor()

    if aad is not None:
        decryptor.authenticate_additional_data(aad)

    # 3) 스트리밍 복호화: ciphertext -> plaintext
    print(f"[*] Streaming decrypt: {in_enc_path} -> {output_path}")
    wrote = 0
    tmp_out = output_path.with_suffix(output_path.suffix + ".part")

    try:
        with in_enc_path.open("rb") as fin, tmp_out.open("wb") as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                p = decryptor.update(chunk)
                if p:
                    fout.write(p)
                    wrote += len(p)

            # finalize()에서 tag 검증
            tail = decryptor.finalize()
            if tail:
                fout.write(tail)
                wrote += len(tail)

        tmp_out.replace(output_path)
        print(f"[*] Decryption completed. bytes={wrote}")
    except Exception:
        # 실패 시 부분 파일 제거(무결성 실패/키 불일치 등)
        try:
            if tmp_out.exists():
                tmp_out.unlink()
        except Exception:
            pass
        raise


# ---------- CLI ----------

def print_usage():
    print("Usage:")
    print("  Encrypt: python tpm_aesgcm_stream.py encrypt <in_file> <out.enc> <out.meta.json> <key_name>")
    print("  Decrypt: python tpm_aesgcm_stream.py decrypt <in.enc> <in.meta.json> <out_file>")
    print("")
    print("Notes:")
    print("  - out.enc 는 바이너리 ciphertext")
    print("  - out.meta.json 에 nonce/tag/key_name 등이 저장됨")
    print("  - TPM_OBJECT_AUTH 환경변수로 auth 입력 생략 가능")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1].lower()

    try:
        if mode == "encrypt":
            if len(sys.argv) != 6:
                print_usage()
                sys.exit(1)
            in_file = sys.argv[2]
            out_enc = sys.argv[3]
            out_meta = sys.argv[4]
            key_name = sys.argv[5]
            encrypt_file_stream(in_file, out_enc, out_meta, key_name)

        elif mode == "decrypt":
            if len(sys.argv) != 5:
                print_usage()
                sys.exit(1)
            in_enc = sys.argv[2]
            in_meta = sys.argv[3]
            out_file = sys.argv[4]
            decrypt_file_stream(in_enc, in_meta, out_file)

        else:
            print_usage()
            sys.exit(1)

    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)
