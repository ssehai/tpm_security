#!/usr/bin/env python3
import os
import sys
import json
import base64
import getpass
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------- 공용 유틸 ----------

def run_cmd(args, input_bytes=None):
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


def get_obj_auth():
    auth = os.environ.get("TPM_OBJECT_AUTH")
    if auth:
        return auth
    return getpass.getpass("TPM object auth (will not echo): ")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def safe_name(name: str) -> str:
    # Linux 기준 최소 치환
    return name.replace("/", "_")


def ts_now_name() -> str:
    """
    파일/폴더명용:
      YYYY-MM-DDTHH-MM-SS  (콜론 ':' 대신 하이픈 '-')
    """
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S")


def unique_path(base: Path) -> Path:
    if not base.exists():
        return base
    i = 1
    while True:
        cand = Path(f"{base}_{i:02d}")
        if not cand.exists():
            return cand
        i += 1


def make_bundle_dir(input_path: Path, created_at_name: str) -> Path:
    """
    번들 폴더명:
      <YYYY-MM-DDTHH-MM-SS>_<입력파일명(확장자 제외)>
    """
    stem = safe_name(input_path.stem)
    bundle = Path(f"{created_at_name}_{stem}")
    bundle = unique_path(bundle)
    bundle.mkdir(parents=False, exist_ok=False)
    return bundle


# ---------- TPM (auth-only) ----------

def ensure_primary(primary_ctx: Path):
    if primary_ctx.exists():
        return
    print("[*] Creating primary key (owner hierarchy)...")
    run_cmd(["tpm2_createprimary", "-C", "o", "-c", str(primary_ctx)])


def tpm_get_random(num_bytes=32) -> bytes:
    print(f"[*] Getting {num_bytes} random bytes from TPM...")
    return run_cmd(["tpm2_getrandom", str(num_bytes)])


def tpm_seal_key(key_bytes: bytes, key_prefix: Path, obj_auth: str, primary_ctx: Path):
    ensure_primary(primary_ctx)

    tmp_key_file = key_prefix.with_suffix(".key.bin")
    pub_file = key_prefix.with_suffix(".pub")
    priv_file = key_prefix.with_suffix(".priv")

    with tmp_key_file.open("wb") as f:
        f.write(key_bytes)

    print("[*] Sealing AES key into TPM (auth-only)...")
    run_cmd([
        "tpm2_create",
        "-C", str(primary_ctx),
        "-u", str(pub_file),
        "-r", str(priv_file),
        "-i", str(tmp_key_file),
        "-p", f"str:{obj_auth}",
        "-a", "fixedtpm|fixedparent|userwithauth",
    ])

    try:
        tmp_key_file.unlink()
    except Exception:
        pass

    print("[*] Sealed key files generated:", pub_file.name, priv_file.name)


def tpm_unseal_key(key_prefix: Path, obj_auth: str, primary_ctx: Path) -> bytes:
    ensure_primary(primary_ctx)

    pub_file = key_prefix.with_suffix(".pub")
    priv_file = key_prefix.with_suffix(".priv")
    if not pub_file.exists() or not priv_file.exists():
        raise FileNotFoundError(f"Sealed key files not found: {pub_file}, {priv_file}")

    ctx_file = key_prefix.with_suffix(".ctx")

    print("[*] Loading sealed key object...")
    run_cmd([
        "tpm2_load",
        "-C", str(primary_ctx),
        "-u", str(pub_file),
        "-r", str(priv_file),
        "-c", str(ctx_file),
    ])

    try:
        print("[*] Unsealing key from TPM (auth-only)...")
        key_bytes = run_cmd([
            "tpm2_unseal",
            "-c", str(ctx_file),
            "-p", f"str:{obj_auth}",
        ])
    finally:
        try:
            run_cmd(["tpm2_flushcontext", "-c", str(ctx_file)])
        except Exception:
            pass
        try:
            ctx_file.unlink()
        except Exception:
            pass

    if len(key_bytes) != 32:
        raise RuntimeError(f"Unexpected key length from TPM: {len(key_bytes)} bytes")
    return key_bytes


# ---------- 스트리밍 AES-GCM ----------

def encrypt_auto_bundle(
    input_path: str,
    aad: Optional[bytes] = None,
    chunk_size: int = 4 * 1024 * 1024,
):
    """
    입력 파일 1개를 받아서:
      - <YYYY-MM-DDTHH-MM-SS>_<file_stem>/ 폴더 생성
      - 폴더 안에 .enc / .meta.json / .pub/.priv / primary.ctx 자동 생성
      - 성공 시 원본 파일 삭제
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    obj_auth = get_obj_auth()
    created_at_name = ts_now_name()

    bundle_dir = make_bundle_dir(input_path, created_at_name=created_at_name)
    base = bundle_dir.name  # 폴더명과 동일 prefix

    enc_path = bundle_dir / f"{base}.enc"
    meta_path = bundle_dir / f"{base}.meta.json"
    key_prefix = bundle_dir / base
    primary_ctx = bundle_dir / "primary.ctx"

    # 여기까지 오면 번들 디렉토리는 생성된 상태.
    # 암호화 실패 시 원본 파일은 삭제하지 않음.
    try:
        # 1) 키 생성
        key = tpm_get_random(32)
        if len(key) != 32:
            raise RuntimeError(f"TPM random length != 32: {len(key)}")

        # 2) nonce
        nonce = os.urandom(12)

        # 3) encryptor
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
        ).encryptor()
        if aad is not None:
            encryptor.authenticate_additional_data(aad)

        # 4) 스트리밍 암호화
        print(f"[*] Bundle dir: {bundle_dir}")
        print(f"[*] Streaming encrypt: {input_path} -> {enc_path}")

        total_in = 0
        total_out = 0

        with input_path.open("rb") as fin, enc_path.open("wb") as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                total_in += len(chunk)
                c = encryptor.update(chunk)
                if c:
                    fout.write(c)
                    total_out += len(c)

            tail = encryptor.finalize()
            if tail:
                fout.write(tail)
                total_out += len(tail)

        tag = encryptor.tag

        # 5) TPM seal
        tpm_seal_key(key, key_prefix=key_prefix, obj_auth=obj_auth, primary_ctx=primary_ctx)

        # 6) meta 저장
        meta = {
            "version": 5,
            "cipher": "AES-256-GCM",
            "created_at_name": created_at_name,  # 복호화 파일명에도 사용

            "source_filename": input_path.name,  # 복호화 시 원본 파일명으로 복원
            "source_stem": input_path.stem,
            "bundle_dir": bundle_dir.name,

            "enc_file": enc_path.name,
            "nonce_b64": b64e(nonce),
            "tag_b64": b64e(tag),
            "aad_b64": None if aad is None else b64e(aad),

            "key_prefix": base,
            "sealed_pub": f"{base}.pub",
            "sealed_priv": f"{base}.priv",
            "primary_ctx": "primary.ctx",

            "chunk_size": chunk_size,
            "plaintext_bytes": total_in,
            "ciphertext_bytes": total_out,
        }
        meta_path.write_text(json.dumps(meta, indent=2))

        print(f"[*] Wrote meta: {meta_path}")
        print("[*] Encryption + TPM seal completed.")

    except Exception:
        # 실패 시 원본은 유지
        print("[!] Encryption failed; original file was NOT deleted.")
        raise

    # 7) 여기까지 성공했으면 원본 삭제
    try:
        input_path.unlink()
        print(f"[*] Original file deleted: {input_path}")
    except Exception as e:
        # 암호화 산출물은 이미 만들어진 상태이므로, 삭제 실패는 경고만
        print(f"[!] Warning: failed to delete original file: {input_path} ({e})")

    print(f"[*] Output bundle: {bundle_dir}")


def decrypt_from_meta_restore_original_name(meta_path: str, chunk_size: Optional[int] = None) -> Path:
    """
    meta.json만 주면 같은 폴더의 .enc / sealed key / primary.ctx를 자동 사용
    출력 파일명은 원본 파일명(source_filename)으로 "그대로" 복원.
    저장 위치: meta.json이 있는 번들 폴더

    주의: 번들 폴더에 같은 이름 파일이 이미 있으면 overwrite 됨(atomic replace).
    """
    meta_path = Path(meta_path)
    if not meta_path.exists():
        raise FileNotFoundError(f"Meta file not found: {meta_path}")

    base_dir = meta_path.parent
    meta = json.loads(meta_path.read_text())

    enc_path = base_dir / meta["enc_file"]
    primary_ctx = base_dir / meta.get("primary_ctx", "primary.ctx")
    key_prefix = base_dir / meta["key_prefix"]

    nonce = b64d(meta["nonce_b64"])
    tag = b64d(meta["tag_b64"])
    aad_b64 = meta.get("aad_b64")
    aad = None if aad_b64 is None else b64d(aad_b64)

    if chunk_size is None:
        chunk_size = int(meta.get("chunk_size", 4 * 1024 * 1024))

    obj_auth = get_obj_auth()

    # 출력 파일명: 원본 파일명 그대로
    source_filename = meta.get("source_filename")
    if not source_filename:
        raise KeyError("meta.json missing 'source_filename'")

    out_path = base_dir / source_filename
    tmp_out = Path(str(out_path) + ".part")

    # 1) 키 unseal
    key = tpm_unseal_key(key_prefix=key_prefix, obj_auth=obj_auth, primary_ctx=primary_ctx)

    # 2) decryptor
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
    ).decryptor()
    if aad is not None:
        decryptor.authenticate_additional_data(aad)

    # 3) 스트리밍 복호화
    print(f"[*] Streaming decrypt: {enc_path} -> {out_path}")

    try:
        with enc_path.open("rb") as fin, tmp_out.open("wb") as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                p = decryptor.update(chunk)
                if p:
                    fout.write(p)

            tail = decryptor.finalize()  # tag 검증
            if tail:
                fout.write(tail)

        # atomic replace (기존 out_path가 있으면 덮어씀)
        tmp_out.replace(out_path)

        print("[*] Decryption completed.")
        print(f"[*] Restored file: {out_path}")
        return out_path

    except Exception:
        try:
            if tmp_out.exists():
                tmp_out.unlink()
        except Exception:
            pass
        raise


# ---------- CLI ----------

def print_usage():
    print("Usage:")
    print("  Encrypt (auto bundle + delete original):")
    print("    python tpm_aesgcm_stream.py encrypt <in_file>")
    print("")
    print("  Decrypt (meta-driven + restore original filename):")
    print("    python tpm_aesgcm_stream.py decrypt <in.meta.json>")
    print("")
    print("Env:")
    print("  TPM_OBJECT_AUTH='...'  (optional)")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1].lower()

    try:
        if mode == "encrypt":
            if len(sys.argv) != 3:
                print_usage()
                sys.exit(1)
            encrypt_auto_bundle(sys.argv[2])

        elif mode == "decrypt":
            if len(sys.argv) != 3:
                print_usage()
                sys.exit(1)
            decrypt_from_meta_restore_original_name(sys.argv[2])

        else:
            print_usage()
            sys.exit(1)

    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
