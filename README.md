# tpm_aesgcm_parallel 테스트 절차

이 문서는 `tpm_aesgcm_parallel` 수정 사항을 검증하기 위해 실제로 수행한 로컬 테스트 흐름을 정리합니다.

## secure_save 모듈 외부 사용

`secure_save.cpp`, `secure_save.h`를 다른 프로그램에 포함하면 프레임 암호화/복호화 로직을 별도 바이너리에서 재사용할 수 있습니다.

- 필요한 의존성: `gstreamer-1.0`, `gstreamer-app-1.0`, OpenSSL(libcrypto), `nlohmann/json` 헤더
- 빌드 예시:

```bash
g++ -std=c++17 -O2 -pthread \
  my_app.cpp secure_save.cpp \
  -lcrypto $(pkg-config --cflags --libs gstreamer-1.0 gstreamer-app-1.0)
```

사용 예시:

```cpp
#include "secure_save.h"

int main() {
    secure_save::SecureSaveConfig cfg;
    cfg.bundle.policy.enabled = true;
    cfg.bundle.policy.server_url = "http://127.0.0.1:8102/approve";
    cfg.bundle.policy.signer_pub = "test_results/policy_keys/signer.pub";
    cfg.object_auth = ""; // TPM_OBJECT_AUTH 환경변수를 사용하려면 비워둡니다.

    secure_save::SecureSave saver(cfg);
    std::vector<secure_save::FramePacket> frames = /* 프레임 구성 */;

    auto bundles = saver.encrypt(frames, "bundles_out", "cam1", 20);
    auto outputs = saver.decrypt("bundles_out", "/dev/shm/tpm_responses", 0, 20000, "both");
}
```

- 프레임 입력: `FramePacket`에 `bgr`(BGR24), `timestamp_ns`, 해상도 정보를 채웁니다.
- TPM 인증: `cfg.object_auth`에 직접 입력하거나 `TPM_OBJECT_AUTH` 환경변수를 사용합니다.
- 정책 서버 사용 시: `cfg.bundle.policy.*`를 채우고 `enabled=true`로 설정합니다.

## 1. 빌드

```bash
make
```

## 2. 전체 테스트 스크립트 (권장)

```bash
make
./run_full_test.sh
```

스크립트는 아래 작업을 자동으로 수행합니다.

- 정책 서명 키 생성 (`--gen-key`)
- 정책 서명 서버 실행
- 암호화 데몬 실행
- 테스트 영상 프레임 전송
- 복호화 요청 및 결과 생성
- 프레임 카운트 검증

진행률 게이지가 전송/암호화/TPM sealing/복호화 단계별로 콘솔에 표시됩니다. 암호화 단계 게이지는 다음 의미를 가집니다.

- `R[...]`: TCP 프레임 수신 진행률
- `S[...]`: 프레임 분리(person/background) 진행률
- `A[...]`: AES-GCM 스트리밍 암호화 진행률
- `T[...]`: TPM sealing 진행률 (start=50%, done=100%)

출력 경로:

- 암호화 번들: `test_results/bundles_test_full8`
- 복호화 결과: `test_results/responses_test_full8`
- 로그: `test_results/logs` (`daemon.log`, `daemon_decrypt.log`, `policy_server.log`, `frame_sender.log`)

스크립트는 종료 시 정책 서버/데몬 프로세스를 정리합니다.

## 3. 수동 테스트 절차

필요하면 아래 순서로 수동 테스트도 가능하도록 유지합니다.

### 3.1 정책 서명 서버 실행 (키 자동 생성)

```bash
mkdir -p test_results/policy_keys
python3 policy_sign_server.py --port 8102 \
  --key test_results/policy_keys/signer.key \
  --pub test_results/policy_keys/signer.pub \
  --gen-key
```

별도 터미널에서 실행합니다.

### 3.2 데몬 실행 (프레임 수신 + 암호화 + HTTP 복호화)

```bash
mkdir -p test_results/bundles_test_full8 test_results/responses_test_full8
./tpm_aesgcm_parallel --daemon \
  --frame-port 5008 \
  --out-dir test_results/bundles_test_full8 \
  --camera-id cam1 \
  --segment-seconds 20 \
  --http-port 8103 \
  --response-dir test_results/responses_test_full8 \
  --policy-server-url http://127.0.0.1:8102/approve \
  --policy-signer-pub test_results/policy_keys/signer.pub
```

### 3.3 테스트 영상 프레임 전송

```bash
./tcp_frame_sender_example \
  --host 127.0.0.1 \
  --port 5008 \
  --video test_video.mp4 \
  --frames 0
```

### 3.4 세그먼트 마감

데몬 터미널에서 `Ctrl+C`로 종료해 세그먼트를 닫습니다.

### 3.5 데몬 재실행 후 복호화 요청

```bash
./tpm_aesgcm_parallel --daemon \
  --frame-port 5008 \
  --out-dir test_results/bundles_test_full8 \
  --camera-id cam1 \
  --segment-seconds 20 \
  --http-port 8103 \
  --response-dir test_results/responses_test_full8 \
  --policy-server-url http://127.0.0.1:8102/approve \
  --policy-signer-pub test_results/policy_keys/signer.pub
```

메타 파일에서 `segment_start_ns`, `segment_end_ns`를 확인한 뒤 아래와 같이 요청합니다. `view=both`를 사용하면 person/background 결과가 모두 생성됩니다. `end_ms`는 ms 단위로 제공하며 내부에서 마지막 프레임까지 포함되도록 처리합니다.

```bash
curl "http://127.0.0.1:8103/decrypt?start_ms=<start_ms>&end_ms=<end_ms>&view=both"
```

### 3.6 복호화 결과 확인

프레임 수 확인:

```bash
ffprobe -v error -select_streams v:0 -count_frames \
  -show_entries stream=nb_read_frames -of default=noprint_wrappers=1 \
  test_results/responses_test_full8/<output_file>.mp4
```

재생 확인:

```bash
ffplay -autoexit -window_title "tpm_aesgcm_parallel output" \
  test_results/responses_test_full8/<output_file>.mp4
```
