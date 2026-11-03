# OMEGA AI 경제 실행 계층 — 로컬 구현

에이전트가 의도를 제출하면 다음 순서로 처리된다.
1. 정책(기본 거부)으로 걸러지고, 사전검사(잔액·예약·시뮬레이션)를 받는다.
2. 상태 머신 + write-ahead 저널을 거쳐 정산 어댑터로 넘어간다.
   - MockLedger: 모의 원장
   - EvmAdapter: 로컬 EVM의 OmegaSettlement 계약(운영자 키 정산)
   - EvmAgentSignedAdapter: OmegaSettlementV2 계약(에이전트 EIP-712 서명 정산, 누구나 중계, 선택적 커널 공동 서명 2-of-2)
3. 저널과 정산 계층을 대사한다.

계산 작업은 omega_compute에서 검증한다. 결정론 VM, 궤적 Merkle 약속, 이분 분쟁, 한 단계 판정, 에스크로·보증금·삭감을 쓴다.

| 구성(지시 3절) | 위치 | 결정 문서 |
| --- | --- | --- |
| A Intent & Policy | `omega_kernel/envelope.py`, `policy.py` | ADR-0001 |
| B Execution Engine | `omega_kernel/kernel.py` | ADR-0001 |
| C Verification | `omega_compute/` (사기 증명), `omega_evm/src/OVM0Step.sol` (체인 위 한 단계 판정자), `omega_evm/src/OVM0StepM.sol` (고정 크기 상태 판정자), `omega_evm/src/OVM0Dispute.sol` (체인 위 이분 분쟁), `Kernel.verify` (저널↔정산 대사) | ADR-0002 |
| D Ethereum Settlement | `omega_kernel/settlement/evm.py`, `evm_crypto.py`, `omega_evm/src/OmegaSettlement.sol` | ADR-0003 |
| E Journal | `omega_kernel/journal.py` | ADR-0001 |
| F Developer API | `omega_kernel/http_api.py` (루프백 HTTP), `python -m omega_kernel demo DIR` | ADR-0001 |

암호학적 보장과 감사 기록의 구분:
- **암호학적 보장**: 의도 인증(HMAC-SHA256 — 공유 키라서 부인 방지 아님), 거래 서명(secp256k1), 궤적 약속(SHA-256 Merkle), 사기 증명(1명의 정직한 도전자 가정).
- **감사 기록일 뿐 보장이 아닌 것**: 저널 해시 체인. 로컬 변조는 탐지하지만, 저널 전체를 다시 쓰는 운영자는 막지 못한다.

## 재현 명령 (Windows, 저장소 루트)

```
PY=python   # Python 3.11+
$PY -X utf8 -B -m pytest tests/test_omega_kernel.py tests/test_omega_compute.py -q -p no:cacheprovider
$PY -X utf8 -B -m pytest tests/test_omega_evm.py -q -p no:cacheprovider -s     # anvil·forge 필요(~/.foundry/bin)
cd omega_evm && forge test --gas-report
$PY -X utf8 -B -m omega_compute.bench OUT.json 20
```

## 실제 결과 (2026-10-28)

- 커널 + 계산 시험: 49 passed, 30 subtests passed (89.96 s)
- EVM 통합: 10 passed. 연속 3회 모두 통과(27.7~44.3 s). 이 시험은 실제 anvil 체인에 배포하고 서명 거래를 보낸다.
- forge: 5 passed. 퍼즈 시험은 256회 실행했다.
- 퍼즈(무작위 프로그램 150개): 거짓 실행자 150/150 패배, 정직한 실행자 150/150 승리.
- 판정자 비용: n = 1,048,569에서 라운드 20, 해시 464, VM 1단계, 판정자 0.90 ms. 같은 계산의 전체 재실행은 10.5 s.

## 실제 결과 (2026-10-29, v2 + 공동 서명 추가 후)

- 커널 + 계산 + EVM 통합 한 번에: 76 passed. 연속 2회 모두 통과(137.7 s, 150.1 s).
  - v2 `AgentSigned` 8개, `AgentSignedCosigned` 9개(같은 8개를 공동 서명 모드로 + 1개)
- forge: 13 passed(v1 5, v2 8).
- 가스(anvil): v1 settle 114,746, v2 settle 100,513, v2 settleCosigned 105,614.
- 커널 정책 밖의 이체를 에이전트가 직접 중계하면, 에이전트 서명만으로는 정산된다(공백 실측). 공동 서명 모드에서는 거부된다.
- 한 단계 판정자 계약(`omega_evm/src/OVM0Step.sol`): 무작위 1,434단계에서 `vm.transition`과 일치한다. 가스는 47,980(작은 상태)~366,499(최악 측정).
  - 시험: `tests/test_omega_evm_step.py`
- 이분 분쟁 계약(`omega_evm/src/OVM0Dispute.sol`): 보증금·여러 도전자를 지원한다. 거짓 주장자·거짓 도전자·정지 뒤 덧붙임·기한 초과·환불·인출을 실제 vm 궤적으로 시험했다. n = 1,504단계 분쟁 전체 가스는 1,462,089(11라운드)이다.
  - 시험: `tests/test_omega_evm_dispute.py`
- 고정 크기 상태 판정자(`omega_evm/src/OVM0StepM.sol`): 스택은 해시 체인, 메모리는 256칸 Merkle 트리다. 무작위 1,434단계에서 `vm.transition`과 일치하고, 위조한 스택·메모리 증거는 거부된다. 같은 상태에서 잰 최악 가스는 529,247(OVM0Step)에서 359,428(깊은 SWAP)로 줄었다. 메모리를 많이 쓰는 상태는 약 0.1배다. 깊은 스택 접근은 최대 2.45배 비싸다. 표는 ADR-0002에 있다.
  - 시험: `tests/test_omega_evm_step_m.py`
- 판정자 인터페이스(`omega_evm/src/IOVM0Referee.sol`): 분쟁 계약은 인터페이스만 보므로 두 판정자 어느 쪽과도 동작한다. 같은 분쟁 시험을 두 판정자에서 모두 돌렸다(23개).
- 단계 상한(`stepCap`, `n ≤ maxSteps + 1`)으로 분쟁 라운드 수에 상한을 두고, 보증금 하한을 실측 가스로 계산한다(`omega_compute/dispute_econ.py`, 표는 ADR-0002).
- 분쟁 기한은 체스 시계 방식이다. 양쪽이 분쟁마다 누적 시간 예산 `clock`을 가지므로, 확정 지연은 라운드 수와 무관하게 window + 2·clock 이하다.
- 전체 회귀 시험(커널·계산·EVM, 단계 상한·체스 시계 포함): 109 passed(328.2 s). forge 16 passed.
- 정직한 자동 실행기(`omega_compute/dispute_agent.py`): 방어자와 감시자. 상태를 갖지 않아 재시작해도 안전하다. 자료 가용성은 `omega_evm/src/OVM0Inbox.sol`이 맡는다. 공개된 계산만 주장할 수 있고, 공개 이벤트가 프로그램·입력을 데이터로 싣는다. 시험은 `tests/test_omega_dispute_agent.py`(10 passed). 분쟁 시험과 함께 37 passed. 공개 기한(daMaxAge)까지 반영한 전체 회귀는 121 passed(382.2 s), forge 16.
  - 전체: Python 80 passed, forge 16 passed(채널 연구 계약 3개 포함)

## 필수 시험 대응 (지시 4절)

| 요구 | 시험 |
| --- | --- |
| 권한 없는 작업 거부 | kernel `AuthorityBypass`; evm `test_onchain_mandate_bounds_kernel` (커널이 허용해도 체인 위 위임 한도가 거부); v2 `test_relayer_key_alone_moves_nothing`, `test_unsigned_intent_is_denied_by_default`, `test_kernel_policy_versus_direct_relay` |
| 지출 한도·만료 | kernel 창 한도·TTL·만료; evm `test_deadline_enforced_on_chain`, `test_owner_revocation_after_acceptance` |
| 중복·재실행 방지 | kernel `ReplayAndDuplicates`; evm 중복 제출·재실행·nonce 재생, 체인 위 `KeyReuse` |
| 잘못된 입력·서명 | kernel `MaliciousInput` (중복 키·실수·초과 크기·잘못된 태그), compute 위조 약속·증명·공개 |
| 거래 실패·불확실 상태 | evm ack 유실, broadcast 전 충돌, 재구성, nonce 탈취 후 재생성 |
| 실행·검증 일관성 | `Kernel.verify` 대사, compute I4/I5 |
| 재시작 후 복구 | kernel `CrashAndRecovery`; evm `test_crash_before_broadcast_then_restart` |

## 보안 가정과 한계

- v1: 운영자 키 탈취 시 피해는 소유자가 건 위임 한도 × 창으로 묶인다.
- v2: 중계자 키 탈취 시 피해는 0이다. 에이전트 키 탈취 시 피해는 위임 한도 × 창이고, 직접 중계로 커널 정책도 우회된다.
- v2 + 공동 서명: 에이전트 키나 커널 키 하나만으로는 0이다. 둘 다 탈취되면 위임 한도 × 창이다.
- 커널 의도 인증은 HMAC 공유 키다. 공동 서명 모드에서는 자금 권한의 근거가 아니다(ADR-0003).
- `LocalTestSigner`는 시험 키 전용이다(상수 시간 아님).
- 분쟁은 동기식 프로토타입이다. 판정자는 체인 위가 아니라 프로세스 안에 있다.
- 프로그램·입력의 데이터 가용성은 가정한다. 프라이버시는 없다.
- 메인넷 chain id는 코드에서 거부한다. 테스트넷 통합·감사는 아직 하지 않았다.
