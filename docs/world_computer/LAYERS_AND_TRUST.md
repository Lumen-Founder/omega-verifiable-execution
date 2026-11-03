# 계층별 입출력·신뢰 경계·권한·지연·경제 한계

- 작성: 2026-10-30(최종 실행 지시 4·7절). 판정: **MAINNET_PREPARATION_IN_PROGRESS**(ADR-0012 §9-3)
- 근거 수치는 모두 결과 파일에서 옮겼다. 결과 폴더는 `…/vexec_20261029/world_final_v{2..6}/`(아래 "v6" 등으로 줄여 적음)이다.
- 증거 등급: 수학 / 모의 / 로컬(anvil) / 포크(메인넷 상태의 로컬 포크) / 실제 네트워크(읽기 전용 측정만) / 외부 감사(없음)

## 1. 계층별 입력·출력·신뢰 경계

| 계층 | 입력 | 출력 | 신뢰하는 것 | 신뢰하지 않는 것(검사) |
| --- | --- | --- | --- | --- |
| L1 계획·오케스트레이터(`plan.py`, `orchestrator.py`) | Plan(작업 DAG, 프로그램·입력, 대금·cover, ttl), 체인 상태 | 서명된 post 요청, reject·void·expire·settle 호출 | 에이전트 키(서명기 객체), 체인 RPC 응답 | 남의 노드·판정 결과(매 tick 다시 읽음), Cannon 판정자 자본(§3), 외부 판정자 코드(가드 R13) |
| L2 출처 그래프(OmegaGraphEscrow 조상 집합) | post의 parents | 노드 상태(claimed → verified → final / rejected / voided / expired) | — | 조상 수(≤ 32), 부모 수(≤ 8), 순환(키 순서) |
| L3 정산(OmegaGraphEscrow) | 예치금, 실행자 지분, 판정자 상태 | 지급·환불·몰수·cover 보상 | 판정자 `getClaim` 상태(가스 상한 200k) | 실행자 주장(판정 전 미지급), 판정자 고장(만료가 막히지 않음, D1) |
| L4a OVM0Dispute + OVM0Step | 주장(약속값), 도전, 이분·응답·증명 | Accepted/Rejected | OVM0Step(OMEGA 코드, 외부 감사 전) | 당사자 주장(이분 탐색 + 한 걸음 재실행) |
| L4b OmegaSuperRootReferee | Optimism 분쟁 게임 주소 | 게임 결과 → Accepted/Rejected | Optimism 공장·등록소·유형 9 게임(프록시, 거버넌스가 바꿀 수 있음) | 등록 게임의 종류·체인·시각, 코드 해시(가드) |
| L4c OmegaCannonGames + OmegaCannonReferee + OmegaBondVault | 사전상태, 주장, 게임 수 | 게임 결과 → Accepted/Rejected, 보증금 | FDG 2.2.0 구현·MIPS64·PreimageOracle(불변), 게스트 재빌드 | 게임 생성자(등록은 생성자만), 다른 입력·상한(약속값 v2), 사전상태(재빌드 확인 R12) |
| L4d `cannon.py`·`cannon_agent.py`·`op_attest.py`(런타임) | Posted·Registered 이벤트, Inbox 공개 | 예약·게임·응답·resolve·정산 거래 | 재빌드한 사전상태, 자기 잔고, 체인 RPC 응답. 게시자가 준 값은 믿지 않음 | 서명기 키(자기 지분·보증금 범위) | 공개 없는 작업은 판단 불가(`unknown`). OP 경로는 방어 없음(ADR-0012 §11-5) |
| L5 권한(§2) | 소유자 설정, 에이전트 서명, 선택 공동서명 | 허용 목록·위임 한도 | 계정 소유자 키 | 에이전트·실행자·릴레이어(허용 목록·한도·서명 검사) |
| L6 DA·보존(OVM0Inbox, `indexer.py`) | 프로그램·입력 공개, 체인 로그 | 해시 사슬 보관 파일, 복원 | 체인 로그 | 보관 파일(체인과 재대조, 변조 경보) |
| L7 재시도·장애 | RPC 오류, 판정자 정지 | 같은 결과(무상태 재실행) | — | RPC 응답(오류는 다음 tick에 다시) |
| L8 감시·모니터(`monitor.py`, `GraphGuard`, `Watchtower`) | 체인 상태, 보관 파일 | 경보 10종, 도전·기각 호출 | 감시자 자신의 실행기(재계산) | 실행자 주장 |
| L9 SDK(`sdk.py`) | 위 전부 | `WorldClient` | — | — |
| L10 비용·지연 | 측정 | §4·§5 | — | — |
| 배포(`deploy.py`) | 체인 설정, 서명된 생성 거래(외부 서명기) | 매니페스트, 검증 결과 | 로컬 빌드(재현 빌드 동일) | 체인의 바이트코드(불변값 가림 대조), 외부 계약(주소·코드 해시 고정) |

## 2. 권한표(배포 계약, 관리자·업그레이드·일시정지 없음)

| 주체 | 할 수 있는 것 | 할 수 없는 것 |
| --- | --- | --- |
| 계정 소유자 | `open`·`deposit`, `setAgent`·`setCosigner`·`setProgram`·`setExecutor`·`setReferee`·`setMandate`, `revoke`, `withdraw`(자기 계정의 묶이지 않은 잔고) | 남의 계정, 묶인 cover·지분, 판정 결과 |
| 에이전트(키는 서명기 안) | 계정의 위임 한도 안에서 post 요청에 서명 | 설정 변경·출금(접근 통제 시험: 6개 설정 모두 NotOwner) |
| 릴레이어 | 서명된 post 요청을 제출 | 서명 위조(BadSignature), 설정 변경 |
| 실행자 | `depositBond`·`withdrawBond`(묶이지 않은 몫), `reserve`·`claim`·`bind` | 계정 자금(대금은 FINAL에서만), 자기 노드 판정 |
| 누구나 | `verify`·`settle`·`reject`·`voidNode`·`expire`·`release`·`slash`(조건이 맞을 때만), OVM0Dispute `challenge`·`timeout`·`refund`·`finalize`, Cannon `create`, FDG의 수·`resolve` | 조건 밖 상태 전이(상태기계·D-rule) |
| Cannon 게임 생성자 | 자기 게임을 `register`(입력·상한·출력 약속값이 뿌리와 맞을 때만) | 남의 게임 등록, 다른 입력·상한으로 등록 |
| 게임 계약(OmegaBondVault 안) | 자기가 넣은 보증금만 `unlock`·`withdraw`(지연 3.5일 뒤) | 다른 게임의 잔고 |
| **외부** Optimism ProxyAdmin·공장 소유자 | 공장·등록소 구현 교체, 유형 9 게임 구현 교체, 게임 무효화(retire·blacklist) | 우리 계약의 상태. 교체가 감지되면 새 게시가 멈춘다(R13). 진행 중 판정에는 영향이 남는다(T30, R13) |
| **외부** Circle(USDC) | 주소 동결·일시정지 | — (T28. DAI는 동결 불가 대안, 포크 미시험) |

## 3. 자산·담보·감시자 정책

- 정산 토큰: USDC(메인넷 제안값). 대금은 FINAL(모든 조상 확정) 뒤에만 실행자에게 간다.
- 실행자 지분: 대금 × 1.25(bondBps 12,500) + cover(계획된 후손 owed 합). 게시부터 만료(기한 + 창 + 2·clock + 유예 1일)까지 묶인다.
- 판정 경로 선택(게시자가 정하고, 시스템은 바꾸지 않는다)
  - OVM0Dispute: 주장 보증금 0.26 ETH, 보상 0.13 ETH(제안값, 근거는 ADR-0012 §6-b). 작은 작업의 기본 경로다.
  - OP 판정자: OP 상태 작업 전용. 게시 직전 외부 코드 해시를 다시 대조한다.
  - Cannon 판정자: 견딜 공격자 자본 W에 대해 방어자·감시자 각각 max(⌈W × 1.0949⌉, 역할의 한 갈래 329.88 / 361.28 ETH)를 갖춘 계정만 쓴다. 없으면 거부한다(SECURITY_REVIEW §10-2).
- 감시자
  - 정직한 감시자 1명 + 체인 활성이 보안 가정이다(R2). 감시자 없이 거짓이 지급되는 것을 포크에서 실측했다(7.0일).
  - 운영 규칙: 서로 독립인 감시자 2곳 이상(다른 RPC 제공자, 다른 장비). 각자 한 시계(OVM0Dispute 3.5일, Cannon 3.5일) 안에 반응한다.
  - Cannon 감시자는 한 갈래 이상(도전자 361.28 ETH)의 ETH를 즉시 쓸 수 있어야 한다.
- 키: 배포·계정 소유자 키는 외부 서명기(하드웨어 지갑)에만 있다. 저장소·로그·대화에 들어오지 않는다.

## 4. 지연(실행·검증·최종 정산)

| 구간 | 값 | 근거(등급) |
| --- | --- | --- |
| OVM0 실행(Python 실행기) | 상한 근처 초당 약 1.7만~2.9만 걸음(이 장비, 부하 의존) | ADR-0012 §6-4(로컬) |
| Cannon 대리인(참 게임 147주장 + 거짓 게임 74주장, 구동기 상태 해시·증명 포함) | 163초 | v6 `RESULT_CANNON_GAME.json`(포크) |
| 블록 포함 | 다음 블록(메인넷 평균 12.2초, 최대 24초) | `NETWORK_MEASURE.json`(실제 네트워크 읽기) |
| OVM0Dispute 최종 정산(분쟁 없음 / 최장) | 창 7일 / 창 + 2·clock = 14일 | `dispute_econ.max_finality_delay`(수학), 로컬 e2e는 짧은 창으로 3,603초 |
| OP 판정자 게시 → final | 604,815초(7.0일) | v6 `RESULT_OP_REFEREE.json`(포크) |
| Cannon 분쟁 없음 → 지급 | 604,920초(7.0일: 시계 3.5일 + 확정 지연 3.5일) | v6 `RESULT_CANNON_ADVERSITY.json` no_watcher(포크) |
| Cannon 최장(양쪽 모든 수 지연) → 기각 | 1,777,756초(20.58일) ≤ 하한 2,095,200초 ≤ 창 25일 | 같은 파일 late_moves(포크) |
| Cannon 보증금 회수 | 확정 뒤 금고 지연 3.5일 | v5·v6 `RESULT_CANNON_GAME.json`(포크) |
| 깊이 k 사슬의 최종 정산(조기 실행) | k·실행 + 창 | ADR-0011 §5(수학) |

## 5. 경제 한계

| 항목 | 값 | 근거 |
| --- | --- | --- |
| 작업당 가스(OVM0, 작은 작업, 4 × 4 그래프, 분쟁 없음) | 전체 수명주기 1,076,374(정산까지 1,021,346) | v10 `RESULT_WORLD.json` scale_layered_4x4(로컬), 정본은 ADR-0012 §6-a |
| 작업당 가스(OP·Cannon, 작은 작업, 분쟁 없음, 실제 USDC) | OP 2,117,235, Cannon 1,760,881 | v10 `RESULT_LIFECYCLE_*.json`(포크) |
| 큰 작업 | 명령 4,096 + 입력 64: 전체 14,641,282. 인박스 한계 publish 16,769,045(거래 상한 2^24 바로 아래, 295,108 B) | v10 `job_lifecycle_sizes` |
| 메인넷 작업당 가스비 p50(p90) | OVM0 0.00049(0.00069), Cannon 0.00080(0.00114), OP 0.00097(0.00137) ETH | v2 `NETWORK_MEASURE.json`의 수수료(p50 0.456 gwei)에 위 가스를 곱함. 한 시점 값 |
| 60M 블록당 작업 | 나눗셈으로 약 56개(처리량 측정 아님). 블록 한도 60,000,000은 포크 블록에서 읽음 | v10 `network.block_gas_limit` |
| post 가스와 조상 수 | 0개 347,240 → 8개 644,874 → 32개(상한) 1,535,714(블록의 5.1 %), 조상 하나당 +36,908 | W1 `RESULT_W1_GRAPH_ESCROW.json` gas_by_ancestors(로컬) |
| void 가스와 조상 수 | 1개 105,532 → 32개 258,439, 조상 하나당 +4,932 | 같은 파일 |
| 큰 그래프의 담보 | cover = 계획된 후손 owed 합. 4 × 4에서 루트 최대 100(comp 10), 합 720 | v10 scale_layered_4x4 |
| OVM0Dispute 정직한 쪽 분쟁 가스(최대) | 1,656,200 가스 상한(실측 1,654,026, 상한 10,000걸음, 전체 상태 최악, OVM0Step) → 50 gwei에서 0.083 ETH. 보상 0.13 ETH가 52.3 gwei까지 1.5배 여유로, 78.5 gwei까지 여유 없이 덮는다. 현재 메인넷 규칙 값이다. Glamsterdam 규칙이면 약 3,625,000 가스(추정, ADR-0012 §6-b. 이전 2,780,000은 calldata 하한을 빠뜨렸다) | v10 `RESULT_DISPUTE_WORST.json`(로컬 실측, 시험이 상한을 단언) |
| Cannon 감시자 가스(거짓 게임 한 판) | 약 950만 가스: attack 34회 8,590,661 + defend 3회 758,355 + claimCredit 2회 156,449 = 9,505,465. 74주장 거짓 게임에서 CHALLENGER_WINS(실행자·감시자 모두 있는 시나리오). 같은 시험에서 거짓 실행자 10,504,905, 정직 실행자 20,797,133(참 게임 147주장 방어 포함) | v10 `RESULT_CANNON_SDK.json` gas_by_party(포크 실측. 이전의 약 940만 가스는 다른 구현의 attack × 37 추정이라 철회, A109) |
| Cannon 자본 잠금 | 한 갈래 329.88~361.28 ETH가 최장 약 24일 + 금고 3.5일 묶임. 연 4 % 기회비용이면 갈래당 약 1.1 ETH | §3 산식(수학, 금리는 가정) |
| OVM0Dispute 자본 잠금 | 주장 0.26 ETH가 분쟁 없으면 7일, 최장 14일. 연 4 %(가정)면 작업당 0.00020 ETH. 동시 16개면 유동성 4.16 ETH | mainnet.json `parameter_basis`, ADR-0012 §6-e(수학) |
| 지분·cover 자본 잠금 | 1.25 × 대금이 reserve부터 expiry 뒤까지(OVM0 기한 + 15일, Cannon·OP 기한 + 26일). cover는 settle까지 | ADR-0012 §6-d(코드 판독) |
| 감시자 운영비 | 상시 RPC 구독 + 재계산 장비. 공개 RPC로 운영 가능함을 확인했으나 비용·가용률은 미측정 | 미측정(X2에서 측정) |
| 수요·가격 | 미측정 → 경제성 UNPROVEN | ADR-0012 §6 |

- 결론: OVM0Dispute로 L1에서 작은 작업 하나를 처리하면 대금과 무관한 고정비가 약 0.0007 ETH(수수료 p50 0.456 gwei의 가스 0.00049 + 주장 보증금 운용비 0.00020, 연 4 % 가정)에 감시자 운영비 몫(미측정)이 더해진다. 대금에 비례하는 지분·cover 운용비는 따로다(ADR-0012 §6-e). Cannon 경로는 분쟁 시 수백 ETH의 자본이 필요해 고가치 작업과 자금 있는 감시자에게만 맞다. L2는 수수료 규칙상 가스비가 약 40배 싸지만(한 시점) 구성·위협 모델을 착수하지 않아 판정하지 않는다(ADR-0012 §6-3).
