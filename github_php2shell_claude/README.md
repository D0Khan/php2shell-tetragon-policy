# PHP2Shell Tetragon 탐지·차단 정책

새싹(SeSAC) 데이터센터 인텔리전스 보안 엔지니어 과정의 팀 프로젝트 **TEFAL**(2026.10.21 ~ 2026.11.10)에서 제가 맡은 부분입니다.
PHP2Shell(CVE-2026-109619) 공격을 eBPF 기반 Tetragon으로 관찰하고, 셸 실행 단계에서 차단하는 정책을 작성했습니다.

팀 전체 결과물(Log4Shell·React2Shell 정책, 백엔드, Grafana 대시보드 등)은 팀 저장소에 있습니다: https://github.com/windfall-0/TEFAL

## 구성

```
php2shell/
  php2shell-uprobe-zifsystem-observe.yaml   # uprobe: libphp.so zif_system, php_exec 호출 관찰
  php2shell-uprobe-popen-observe.yaml       # uprobe: libc popen, system 호출 관찰
  php2shell-kprobe-execve-observe.yaml      # kprobe: apache가 셸·명령을 실행하는지 관찰
  php2shell-lsm-bprmcheck-block.yaml        # BPF-LSM: apache의 셸 실행 요청 거부 (Override)
  kustomization.yaml                        # kprobe + LSM 정책 일괄 적용
tetra-sync.sh                               # uprobe 경로의 호스트 PID 갱신 + 정책 적용
```

## 정책 설계

PHP 함수 호출부터 셸 실행 직전까지 네 지점에 정책을 걸었습니다.

| 지점 | 정책 | 동작 |
|---|---|---|
| PHP 엔진 (zif_system, php_exec) | uprobe | 관찰 (Post) |
| libc (popen, system) | uprobe | 관찰 (Post) |
| 시스템 콜 (sys_execve) | kprobe | 관찰 (Post) |
| 실행 검사 (bprm_check_security) | BPF-LSM | 차단 (Override, -EPERM) |

처음에는 프로세스를 종료하는 SIGKILL 방식도 비교했지만, 웹 요청을 처리하는 Apache 워커까지 종료될 수 있었습니다.
그래서 앞의 세 지점은 실행 흐름만 기록하고, 차단은 LSM 단계에서 셸 실행 요청만 거부하도록 했습니다.

## tetra-sync.sh

uprobe 정책은 컨테이너 내부 라이브러리를 `/procRoot/<호스트 PID>/root/...` 경로로 지정합니다.
파드가 재생성되면 호스트 PID가 바뀌어 기존 경로가 무효가 되고, 정책을 다시 적용하면 `load_error`가 발생했습니다.
이 스크립트는 다음 순서로 경로를 맞춘 뒤 정책을 다시 적용합니다.

1. 라벨로 대상 파드를 찾고, 파드가 떠 있는 노드와 파드 UID를 확인
2. 같은 노드의 Tetragon 에이전트에서 `/procRoot` 아래 PID를 돌며, 후킹 대상 파일이 있고 cgroup에 파드 UID가 들어 있는 PID를 찾음 (후보 중 가장 작은 PID)
3. uprobe YAML의 `/procRoot/<PID>/root` 부분을 찾은 PID로 바꿈
4. 기존 uprobe 정책을 지우고 다시 적용한 뒤, 각 폴더의 kustomization.yaml 적용

```bash
./tetra-sync.sh         # PID 갱신 + 정책 적용
./tetra-sync.sh --dry   # PID 갱신만 (적용·삭제 안 함)
```

스크립트는 PHP2Shell용으로 먼저 작성한 뒤, 팀원의 Log4Shell용 스크립트를 같은 방식으로 합치고 React2Shell을 추가해 세 환경 공통으로 만들었습니다.
이 저장소에는 PHP2Shell 폴더만 있으며, 없는 폴더는 스크립트가 건너뜁니다.

## 실험 환경

- Kubernetes 클러스터 (팀 공용, Kubespray로 구성), Tetragon, 네임스페이스 `vuln-lab`
- 대상: PHP + Apache 파드 (`app=php2shell`), PHP 8.4.26과 8.5.11에서 공격 재현 확인
- 공격 재현에 사용한 공개 PoC는 이 저장소에 포함하지 않았습니다.

## 한계

- 실행 시점에 PID를 맞추는 반자동 방식입니다. 파드 재생성을 감지해 자동으로 실행하는 기능은 없습니다.
- LSM 차단은 셸 실행 요청만 거부합니다. 메모리 오염 등 그 이전 단계는 막지 못하고, 차단 이후에도 이미 손상된 워커가 종료될 수 있습니다.
- 탐지율, 오탐률, 성능 영향은 측정하지 않았습니다. 기능 검증 수준의 결과입니다.
