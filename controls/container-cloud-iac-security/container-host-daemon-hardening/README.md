# PSB-CONTAINER-003: Container host and daemon hardening

## このcontrolを一枚で理解する

### セキュリティ上の問題

Production container hostがgeneral-purpose化し、patch遅延、public daemon API、runtime socket、弱いfile権限、kernel isolation欠落、broad adminを抱えると、1 containerの侵害がnode takeoverへ拡大する。

### 誰から、または何から守るか

Compromised workload、external attacker、stolen operator identity、malicious local process、patch／inventory／audit障害、改変されたboot chainから守る。

### 何が対象か

Linux production／shared container hostのOS、kernel、Docker／containerd／CRI-O daemon、socket、設定・binary・storage・service unit、management ingress、operator、audit、hardware trust。

### 何をするか

Hostを専用・最小化して更新し、daemon管理面、user namespace、seccomp／LSM、protected path、operator RBAC、private network、immutable audit、secure boot／attestationを検証する。

### 成功状態

9 checksがPASSし、host takeover経路はFAIL、unsupported platformは`NOT_CHECKED`、collector・schema・freshness異常は`ERROR`としてcleanと区別される。

### 対象外・残余リスク

Offline fixtureはlive host enforcementを証明せず、workload admission、registry、image scan、runtime behavior、application vulnerability、SLSA Build securityは別controlで扱う。

## 何を守るcontrolか

Containerはhost kernelとdaemonに依存します。Podやcontainerのsecurity contextが安全でも、
host上のDocker socketが公開されている、containerd binaryが書換可能、kernelが未patch、
operatorがどこからでも全nodeを管理できるなら、workload側の制約を迂回できます。

このcontrolはdeveloper PCではなく、本番または共有container nodeのhost側を対象にします。
developer endpointは`PSB-SOURCE-001`、CI build sandboxは`PSB-BUILD-001`、workload
admissionは`PSB-CONTAINER-001`の責務です。

## まず実行するコマンド

```bash
make verify-control CONTROL=PSB-CONTAINER-003
```

通常検証はhostへ接続せず、sanitizedなLinux host policy、観測証跡、exception、
evidence healthを固定時刻でoffline評価します。

| 終了コード | 意味 |
|---:|---|
| `0` | 全9 checksが`PASS` |
| `1` | 1件以上のhardening違反が`FAIL` |
| `2` | malformed、stale、incomplete、unavailable evidenceによる`ERROR` |
| `3` | unsupported platformまたは有効な限定exceptionにより`NOT_CHECKED` |

`NOT_CHECKED`は許可や準拠を意味しません。provider adapterの追加またはexception解消まで
組織側の未確認事項として残します。

## 9つのatomic check

| Check | 確認内容 |
|---|---|
| `HST-001` | Dedicated minimal hostとreview済みservice inventory |
| `HST-002` | OS、kernel、runtime、daemonのsupport／patch baseline |
| `HST-003` | Private authenticated daemon endpointとsocket非mount |
| `HST-004` | Rootless／user namespace、kernel lockdown、限定exception |
| `HST-005` | Config、binary、socket、storage、service unitのowner／mode／digest |
| `HST-006` | Default seccomp、SELinux／AppArmor、kernel module policy |
| `HST-007` | Exact operator RBAC、management network、immutable audit |
| `HST-008` | Secure／measured boot、TPM node identity、pool attestation |
| `HST-009` | Evidence completeness、freshness、`NOT_CHECKED`／`ERROR`分離 |

## Secure fixture

`secure/`は次のprovider-neutral状態を表します。

- production container workload専用hostで、review済みserviceだけが動く。
- exact OS／kernel／runtime／daemon versionがsupportedでpatch deadline内にある。
- daemonはrestrictive modeのlocal Unix socketだけで待受け、workload mountは0件。
- user namespace、kernel lockdown、default seccomp、AppArmor enforcingを使う。
- protected pathのtype、owner、group、mode、file digestがpolicyと一致する。
- exact operator groupがprivate management CIDRからだけ管理し、required eventを監査する。
- Secure Boot、measured boot、TPM-backed node identity、pool-bound attestationを持つ。

`insecure/`はgeneral-purpose workload、unreviewed service、unsupported stack、public
unauthenticated TCP daemon、workload socket mount、disabled isolation、writable／tampered
runtime file、wildcard admin、public management source、mutable audit、failed attestationを
意図的に含みます。productionへ適用してはいけません。

## Exceptionの扱い

Rootlessとuser namespaceの両方を使えないplatform limitationは、次の全条件を満たす
場合だけ`NOT_CHECKED`として識別します。

- checkはexact `HST-004`、scopeはexact node pool。
- owner、ownerと異なるapprover、具体的reasonがある。
- 作成から30日以内に失効する。
- dedicated host、seccomp、enforcing LSM、restricted management networkを補償策に持つ。

Exceptionは`PASS`へ変換しません。missing、broad、expired、self-approvedなrecordは
`FAIL`です。将来`PSB-GOV-002`のshared exception enforcementへ接続します。

## Provider adapter contract

Live adapterはroot権限を使う変更scriptではなく、read-only collectorとして次を
正規化します。

1. Host purpose、workload class、enabled service。
2. OS release、kernel、runtime、daemon version、support、last security patch。
3. Listener、authentication、exposure、runtime socket、workload mount count。
4. Rootless／user namespace、kernel lockdown、seccomp、LSM、module policy。
5. Protected pathの`lstat` type、UID／GID名、mode、review対象fileのSHA-256。
6. Operator role、node scope、source address、audit rulesとcollector status。
7. Secure Boot、measured boot、TPM identity、attestation、node pool binding。
8. 各sourceのstatus、completeness、last success time。

Unsupported platformの判定自体にはfreshな`platform-inventory` sourceを要求します。
Collectorに必要な権限がない、paginationやnamespaceを観測できない、commandが失敗した
場合は空値を安全状態として返さず、healthを非`ok`にして`ERROR`へ送ります。

## 他controlとの境界

- `PSB-CONTAINER-001`: workload security contextとadmission時のruntime socket mount禁止。
- `PSB-CONTAINER-002`: registry transport、authorization、mutation、audit、image lifecycle。
- `PSB-CONTAINER-004`: Falco／Sysdig event、sensor health、alert delivery。Live sensorの
  installation privilege、driver、kernel compatibilityはこのhost controlの後続adapter。
- `PSB-DETECT-001`: hostやimage vulnerability scannerの安全な実行。Patch policyは
  scannerのclean結果を代替しない。
- `PSB-BUILD-001`: untrusted build jobのsandbox。Production node hardeningとは別境界。

## Framework mapping

NIST SP 800-190 September 2017の`4.3.1`、`4.3.5`、`4.5.1`〜`4.5.5`、
`4.6`へ、直接実行証跡を持つcheckだけをmappingします。これはNISTまたはcontainer
platform全体の準拠を意味しません。

CIS Docker Benchmark v1.8.0はDocker固有の主要候補ですが、authorized official PDF、
SHA-256、recommendation inventory、reuse termsのreviewが完了するまでmappingしません。
SLSA Build levelはproduction container hostを対象にしないためmappingしません。

## 参考資料

- [NIST SP 800-190 registry](../../../frameworks/nist-sp-800-190/README.md)
- [Container Security Source Allocation](../../../docs/CONTAINER_SECURITY_SOURCE_ALLOCATION.md)
- [OWASP Docker Security Cheat Sheet allocation](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-001)
- [PSB-CONTAINER-001](../container-admission-baseline/README.md)
- [PSB-CONTAINER-002](../container-registry-security/README.md)
- [PSB-CONTAINER-004](../runtime-threat-detection/README.md)

## Limitations

- Offline E3 evidenceはlive host、daemon、firewall、audit、TPMのenforcementを証明しません。
- Version baselineとpatch deadlineはorganization policyであり、live vendor advisory feedではありません。
- Managed control planeとWindows hostはprovider-specific adapterまで`NOT_CHECKED`です。
- Hardware attestationを提供できないplatformは自動的に安全とは扱われません。
- Valid exceptionも`PASS`ではなく、期限内に解消または再評価が必要です。
