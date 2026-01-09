#!/usr/bin/env python3
import os
import sys
import json
import base64
import getpass
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    """
    오너 계층(-C o)에 primary key가 없으면 새로 만들고,
    있으면 기존 ctx 파일을 사용.
    실제로는 persistent handle을 쓰는 편이 더 깔끔하지만,
    여기선 예제 단순화를 위해 ctx 파일만 사용.
    """
    if Path(primary_ctx).exists():
        return
    print("[*] Creating primary key (owner hierarchy)...")
    run_cmd(["tpm2_createprimary", "-C", "o", "-c", primary_ctx])


# ---------- TPM 관련 함수 ----------

def tpm_get_random(num_bytes=32):
    """
    TPM RNG로부터 num_bytes 만큼 랜덤 바이트 획득.
    AES-256 키용으로 32바이트 사용.
    """
    print(f"[*] Getting {num_bytes} random bytes from TPM...")
    return run_cmd(["tpm2_getrandom", str(num_bytes)])

def tpm_seal_key(key_bytes: bytes, key_name: str, obj_auth: str, pcr_selection: str = "sha256:7", primary_ctx="primary.ctx"):
    """
    key_bytes를 TPM primary key 아래 sealed object로 만들기.
    결과로 key_name.pub, key_name.priv 파일이 생성됨.
    """
    ensure_primary(primary_ctx)

    tmp_key_file = f"{key_name}.key.bin"
    with open(tmp_key_file, "wb") as f:
        f.write(key_bytes)

    policy_file = f"{key_name}.policy"
    print(f"[*] Building PCR+Auth policy: {policy_file} (PCR={pcr_selection})")
    tpm_build_pcr_auth_policy(policy_file, pcr_selection)

    print(f"[*] Sealing AES key into TPM (key_name={key_name}) with auth + PCR policy...")
    # auth 없이, 고정 속성 정도만 부여한 sealed object
    run_cmd([
        "tpm2_create",
        "-C", primary_ctx,           # parent: primary
        "-u", f"{key_name}.pub",
        "-r", f"{key_name}.priv",
        "-i", tmp_key_file,
        "-L", policy_file,          # 정책 적용
        "-p", f"str:{obj_auth}",    # 객체 authValue 적용
        "-a", "fixedtpm|fixedparent|adminwithpolicy|userwithauth",
    ])

    # 평문 키 파일은 바로 삭제
    os.remove(tmp_key_file)
    print("[*] Sealed key files generated:", f"{key_name}.pub", f"{key_name}.priv", policy_file)

def tpm_unseal_key(key_name: str, obj_auth: str, pcr_selection: str = "sha256:7", primary_ctx="primary.ctx") -> bytes:
    """
    key_name.pub / key_name.priv 로부터 TPM sealed object를 load + unseal해서
    원래 key_bytes를 복원.
    """
    ensure_primary(primary_ctx)

    pub = Path(f"{key_name}.pub")
    priv = Path(f"{key_name}.priv")
    if not (pub.exists() and priv.exists()):
        raise FileNotFoundError(
            f"Sealed key files not found: {pub}, {priv}"
        )

    ctx_file = f"{key_name}.ctx"
    print(f"[*] Loading sealed key object (key_name={key_name})...")
    run_cmd([
        "tpm2_load",
        "-C", primary_ctx,
        "-u", str(pub),
        "-r", str(priv),
        "-c", ctx_file,
    ])

    sess = "policy_sess.ctx"
    try:
        print(f"[*] Starting policy session (PCR={pcr_selection})...")
        run_cmd(["tpm2_startauthsession", "--policy-session", "-S", sess])
        run_cmd(["tpm2_policypcr", "-S", sess, "-l", pcr_selection])
        run_cmd(["tpm2_policyauthvalue", "-S", sess])

        print("[*] Unsealing key from TPM with policy session + auth...")
        key_bytes = run_cmd([
            "tpm2_unseal", 
            "-c", ctx_file,
            "-p", f"session:{sess}+str:{obj_auth}",
        ])
    finally:
        # 세션/오브젝트 정리
        try:
            run_cmd(["tpm2_flushcontext", sess])
        except Exception:
            pass 
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

def tpm_build_pcr_auth_policy(policy_file: str, pcr_selection: str):
    """
    PolicyPCR + PolicyAuthValue를 포함하는 policy digest를 생성해서 policy_file에 저장.
    이 policy는 '현재 PCR 값'에 바인딩됩니다.
    """
    sess = "policy_sess.ctx"
    try:
        run_cmd(["tpm2_startauthsession", "--policy-session", "-S", sess])
        # 현재 PCR 값을 기반으로 PolicyPCR 적용
        run_cmd(["tpm2_policypcr", "-S", sess, "-l", pcr_selection])
        # authValue를 요구하도록 정책에 포함
        run_cmd(["tpm2_policyauthvalue", "-S", sess])
        # 정책 다이제스트를 파일로 저장
        run_cmd(["tpm2_policygetdigest", "-S", sess, "-L", policy_file])
    finally:
        # 세션 정리(실패해도 시도)
        try:
            run_cmd(["tpm2_flushcontext", sess])
        except Exception:
            pass

# ---------- AES-GCM 파일 암/복호화 ----------
def get_obj_auth():
    auth = os.environ.get("TPM_OBJECT_AUTH")
    if auth:
        return auth
    return getpass.getpass("TPM object auth (will not echo): ")

def encrypt_file(input_path: str, output_path: str, key_name: str):
    """
    1) TPM RNG로 AES-256 키 생성
    2) AES-GCM-256으로 input_path 파일 암호화
    3) 암호 결과(JSON) output_path에 저장
    4) 같은 키를 TPM에 seal (key_name 기준으로 .pub/.priv 생성)
    """
    input_path = Path(input_path)
    output_path = Path(output_path)
    pcr_selection = os.environ.get("TPM_PCR_SELECTION", "sha256:7")
    obj_auth = get_obj_auth()

    # 1. TPM에서 32바이트 랜덤 = AES-256 키 생성
    key = tpm_get_random(32)
    if len(key) != 32:
        raise RuntimeError(f"TPM random length != 32: {len(key)}")

    # 2. 평문 파일 읽기
    print(f"[*] Reading plaintext from {input_path} ...")
    plaintext = input_path.read_bytes()

    # nonce / AAD 설정
    nonce = os.urandom(12)    # GCM 권장 96-bit nonce
    aad = None                # 필요하면 bytes로 세팅

    # 3. AES-GCM-256 암호화
    print("[*] Encrypting with AES-GCM-256...")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # cryptography의 AESGCM는 ciphertext+tag가 합쳐진 형태로 반환

    # 4. 암호 결과를 JSON으로 저장
    enc_obj = {
        "version": 1,
        "key_name": key_name,
        "pcr_selection": pcr_selection,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": None if aad is None else base64.b64encode(aad).decode("ascii"),
    }

    print(f"[*] Writing encrypted file to {output_path} ...")
    output_path.write_text(json.dumps(enc_obj, indent=2))

    # 5. 키를 TPM에 seal
    tpm_seal_key(key, key_name, obj_auth=obj_auth, pcr_selection=pcr_selection)
    print("[*] Encryption+seal completed.")


def decrypt_file(input_path: str, output_path: str):
    """
    1) 암호화 JSON 파일에서 key_name, nonce, ciphertext, aad 추출
    2) TPM에서 key_name 기준으로 sealed key unseal
    3) AES-GCM-256으로 복호화
    4) 복호화 결과를 output_path에 저장
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    print(f"[*] Reading encrypted file from {input_path} ...")
    enc_obj = json.loads(input_path.read_text())

    obj_auth = get_obj_auth()
    pcr_selection = enc_obj.get("pcr_selection", "sha256:7")

    key_name = enc_obj["key_name"]
    nonce = base64.b64decode(enc_obj["nonce"])
    ciphertext = base64.b64decode(enc_obj["ciphertext"])
    aad_b64 = enc_obj.get("aad")
    aad = None if aad_b64 is None else base64.b64decode(aad_b64)

    # TPM에서 키 unseal
    key = tpm_unseal_key(key_name, obj_auth=obj_auth, pcr_selection=pcr_selection)
    print("[*] Decrypting with AES-GCM-256...")
    aesgcm = AESGCM(key)

    # 태그 검증 실패 시 여기서 예외 발생
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    print(f"[*] Writing plaintext to {output_path} ...")
    output_path.write_bytes(plaintext)
    print("[*] Decryption completed.")


# ---------- CLI 인터페이스 ----------

def print_usage():
    print("Usage:")
    print("  Encrypt: python tpm_aesgcm.py encrypt <in_file> <out_file> <key_name>")
    print("  Decrypt: python tpm_aesgcm.py decrypt <in_file> <out_file>")
    print("")
    print("  - <key_name>은 sealed key 파일 이름 prefix로 사용됩니다.")
    print("    예: key_name=backup1 → backup1.pub, backup1.priv 생성")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1].lower()

    try:
        if mode == "encrypt":
            if len(sys.argv) != 5:
                print_usage()
                sys.exit(1)
            in_file = sys.argv[2]
            out_file = sys.argv[3]
            key_name = sys.argv[4]
            encrypt_file(in_file, out_file, key_name)

        elif mode == "decrypt":
            if len(sys.argv) != 4:
                print_usage()
                sys.exit(1)
            in_file = sys.argv[2]
            out_file = sys.argv[3]
            decrypt_file(in_file, out_file)

        else:
            print_usage()
            sys.exit(1)
    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)