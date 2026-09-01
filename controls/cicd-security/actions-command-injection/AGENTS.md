# PSB-CICD-002 implementation instructions

この file は `PSB-CICD-002` に固有の実装境界を定める。repository root と
`controls/AGENTS.md` を先に読み、共通規約をここへ複製しない。

## Control essence

- Domain は `cicd-security` である。
- 対象は GitHub Actions workflow の `run:` scalar と、GitHub expression evaluator から
  runner shell へ値が渡る境界である。
- 禁止する状態は `${{ ... }}` を `run:` へ直接書き、event metadata、workflow input、
  matrix value、output 等を生成済み shell source の一部にすることである。
- 必要な値は `env:` へ割り当て、shell では quoted variable または固定形式の argument として使う。
  値が処理の選択に使われる場合は、文字列から command を組み立てず、小さな allowlist で分岐する。
- Attacker-controlled property の不完全な list は作らない。`run:` 内の直接 expression を一律に拒否する
  単純な rule を維持する。
- Security 効果は、採用先の実 workflow を修正し、review 済み verifier を required check として実行する
  ことから生まれる。Secure fixture の `PASS` や file copy だけを organization adoption と扱わない。

## Supported assumptions

- 最小 profile は GitHub.com Actions、`.yml`／`.yaml` workflow、GitHub-hosted Ubuntu、Bash／POSIX shell、
  Python 3.10+ である。Local test は macOS または Linux で実行できるようにする。
- `run: command`、literal block `run: |`、folded block `run: >` を対象にする。
- YAML alias、flow style、解析不能な multiline quoted scalar、tab indentation 等を正しく解析できない場合は
  `ERROR` にする。推測して clean にしない。
- PowerShell、Windows `cmd`、Composite Action の `runs.steps[*].run` を support するときは、shell 固有の
  safe consumption、fixture、期待結果、残余リスクを別 profile として追加する。既存 Bash pattern を
  そのまま安全と推測しない。
- GitHub expression／workflow syntax の仕様変更、または新しい YAML form を追加するときは、対象の公式仕様、
  supported form、harmless negative input、fail-closed behavior を確認してから実装する。不明な form は
  unsupported として明記する。

この前提で実装できない adopter は、曖昧な互換 layer を足すのではなく、unsupported scope として記録する。

## Chosen implementation profile

この control は小さな executable configuration profile と static verification を採用する。

1. `secure/workflow.yml` は expression を `env:` へ移し、quoted variable と allowlist を使う copyable pattern
   を示す。
2. `insecure/workflow.yml` は直接補間の危険例だけを隔離して示し、`.github/workflows` へ配置しない。
3. `scripts/verify.py` は Python standard library だけで `run:` scalar を抽出し、直接 expression を拒否する。
4. `tests/test.sh` は secure、finding、verification error を人が読めるケースで区別する。

PyYAML、scanner framework、container、package manager、network access をこの rule のためだけに追加しない。
Restricted parser で安全に扱えない実用上の syntax が確認された場合だけ、documented gap、fixture、dependency
trust を review して parser 変更を検討する。

## Minimal adoption path

README は mandatory one-page summary の直後から、次の最短経路を具体的に示す。

1. Prerequisite として GitHub Actions workflow、実際に使う shell、Python 3.10+、workflow security check の
   administrator を確認する。
2. `scripts/verify.py` を repository-owned security script として copy または固定参照する。既存 file を
   無断で上書きせず、内容を review して配置する。
3. `.github/workflows` の全 `run:` を検査し、直接 expression を `env:` へ移す。
4. Shell variable を quote する。動作を選ぶ input は `case` 等で許可値へ限定し、`eval`、補間した
   `bash -c`、動的 command string を使わない。
5. `python3 <copied-verifier> .github/workflows` を実行し、`0=accepted`、`1=finding`、
   `2=input／parser／execution error` を確認する。
6. 同じ command を既存の unprivileged CI job に追加し、`1` と `2` の両方を merge blocking にする。
   Verifier と policy を同じ変更で自由に弱められないよう、trusted template、CODEOWNERS、ruleset、または
   `PSB-CICD-003` の review 済み scanner gate と組み合わせる。
7. Harmless payload を title／branch／manual input 相当の environment value として渡し、文字列として
   出力されることと、追加 command が実行されないことを確認する。

Recovery は finding の式を `env:` へ移して consumption point を quote すること、または unsupported syntax を
review 可能な scalar へ書き換えることである。Verifier を skip したり exit `2` を clean に変換したりしない。
Rollback は copy した verifier と CI wiring だけを adopter-owned review で外す。Global Git、shell、IDE、OS、
Python setting を変更しない。Rollback 後も server-side static analysis と workflow review は必要である。

## Security decision semantics

- `run:` scalar に直接 `${{ ... }}` が一つでもあれば `FAIL`／exit `1` とする。Expression source の
  allowlist は設けない。
- 対象 file 不在、読取不能、対象外 suffix、`run:` 不在、unsupported syntax、invalid encoding、parser failure
  は `ERROR`／exit `2` とする。
- Expression が `env:`、`if:`、`concurrency:` 等の非 `run:` field にあるだけでは、この control の
  command-injection finding にしない。
- `env:` を使ったことだけで shell safety を証明したと扱わない。Unquoted expansion、`eval`、`bash -c`、
  sourced file、generated script、subprocess argument construction は別途 code review が必要である。
- Verifier output は path、line、正規化した expression、decision に限定する。Runtime value、secret、event body、
  raw provider payload を出力しない。

## Atomic checks

既存参照を安定させるため `INJ-001..004` を不要に renumber しない。

- `INJ-001`: `run:` scalar に直接 Actions expression がないことを自動検証する。
- `INJ-002`: 必要な値を `env:` へ移し、shell 固有の quoting／allowlist で data として扱う secure pattern を
  示す。現在の verifier は任意 shell code の安全な quoting まで証明しないため、その限界を隠さない。
- `INJ-003`: `concurrency` 等の非実行 field を command injection と誤検出しない。
- `INJ-004`: 読取／parser／unsupported syntax failure を clean と区別する。

Check の意味を変更する場合は `control.yaml` の required state、context、verification、mapping、README の
claim を同時に揃える。Static verifier が証明しない property を `automated` evidence として追加しない。

## Relationship to other controls

- `PSB-CICD-001` は third-party Action の immutable SHA pinning を所有する。本 control に Action update policy を
  追加しない。
- `PSB-CICD-003` は zizmor の pinning、repository scanner workflow、untrusted gate と privileged SARIF reporting
  の分離を所有する。本 control は同じ scanner orchestration を複製せず、直接 expression rule と最小 local
  verifier を所有する。
- `PSB-CICD-004` は `GITHUB_TOKEN` と OIDC permission の最小化を所有する。権限最小化は injection 成功時の
  impact を下げるが、直接補間を許可する理由にはならない。
- `PSB-CICD-005` は fork／untrusted PR と privileged job の分離を所有する。本 control では
  `pull_request_target`、secret、runner trust の一般 policy を再実装しない。
- `PSB-BUILD-001` は job 開始後の credential、sandbox、egress、telemetry containment を所有する。
- Composite Action、external Action の `with:` input 処理、workflow から呼ばれる repository script の一般的な
  command injection は本 verifier の対象外である。README で明記し、完全な shell injection prevention を
  claim しない。

## Verification strategy

Test は direct expression boundary の meaningful behavior に限定する。

- Quoted `env:` consumption と fixed allowlist の secure fixture を accepted にする。
- Single-line、literal block、folded block、line をまたぐ expression の直接補間を rejected にする。
- PR title、branch、manual input を模した inert metacharacter payload が data のままで、marker command を
  実行しないことを Bash self-test で確認する。
- `concurrency` 等の非実行 expression は accepted にする。
- Missing input、no workflow file、no `run:`、unreadable／invalid UTF-8、alias、flow style、unsupported multiline
  quoted form、tab indentation を exit `2` にする。
- Secure fixture、insecure fixture、実 repository workflow の検査を分け、fixture success を live adoption
  evidence にしない。

README の文字列だけを確認する test、手書き JSON の `secure: true`、常に成功する no-op、実 credential、
production event、外部 network を使う test は追加しない。Parser rule を変更した場合は、その rule が防ぐ
具体的 bypass または false positive の fixture を追加する。

## Live verification and evidence

- Reference evidence は secure／insecure fixture と verifier の regression output である。
- Organization adoption の evidence は、review 済み verifier identity、実 `.github/workflows` 全体の current
  result、取得時刻、required-check／ruleset の current state、対象 revision が結び付いた sanitized record
  である。
- Fixture の `ACCEPTED`、README、synthetic workflow を実 repository の安全性として提示しない。
- Live GitHub setting を確認していない場合、required check や CODEOWNERS が有効だと推測しない。

## Required verification after changes

Repository root から少なくとも次を実行する。

```bash
bash controls/cicd-security/actions-command-injection/tests/test.sh
make verify-control CONTROL=PSB-CICD-002
make validate-controls
```

`control.yaml` の check、mapping、status、implementation path を変更した場合は canonical generator を実行し、
`PSB-CICD-002` に由来する index、mapping、checklist 差分だけを review する。Test を通すために direct
expression prohibition または fail-closed behavior を弱めない。
