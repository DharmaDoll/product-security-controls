# PSB-GOV-002: セキュリティ例外を狭く・承認付き・期限付きにする

## このcontrolを一枚で理解する

### セキュリティ上の問題

セキュリティ検査を回避する例外が曖昧、自己承認、恒久化、または台帳外になると、当初とは無関係な対象まで保護を失い、期限切れリスクが残り続ける。

### 誰から、または何から守るか

リリースを急ぐ担当者による過剰scope、承認者の誤認、悪意ある回避、例外台帳の欠落・改ざん、時刻経過による無効化漏れから守る。

### 何が対象か

control/check ID、対象とenvironment、owner、risk reviewer、approver、理由、risk、代替control、作成・失効日時、承認・是正ticket、完全な例外台帳。

### 何をするか

共通YAML契約で例外を一件ずつ記録し、repository catalogとのID整合、独立承認、最大寿命、exact scope、台帳の完全性・freshness・SHA-256を機械検証する。

### 成功状態

有効・失効間近・期限切れ・不正を評価時刻から再計算でき、期限切れと不正はFAIL、台帳欠落・取得失敗・改ざん・秘密情報混入はERRORになる。

### 対象外・残余リスク

fixtureはticket systemやpolicy engineを変更せず、同じ権限で例外と台帳hashを同時改ざんする攻撃、信頼時刻、実環境への強制、既存独自形式の移行は別途必要。

## Goal

例外を「検査を無効化する設定」ではなく、誰がどのriskをどの対象についていつまで
受け入れたかを検証できる短寿命のdecision recordにします。各controlは独自の例外schemaを
増やさず、`psb-security-exception/v1`を参照し、control固有の判断だけを維持します。

このcontrolは4つのviewを評価時刻から導出します。

| view | gateでの扱い | 意味 |
|---|---|---|
| `ACTIVE` | 利用可能 | 現在有効で、失効警告期間より前。 |
| `EXPIRING` | 利用可能だが要対応 | 現在有効だが、policyの警告期間内。 |
| `EXPIRED` | `FAIL` | 期限が過ぎており、手動削除を待たず利用不可。 |
| `INVALID` | `FAIL` | scope、承認、risk、期間、ticket、catalog IDなどがpolicy不適合。 |
| 台帳・parser・証跡異常 | `ERROR` | 評価不能。例外なし、またはcleanとは扱わない。 |

## 安全でない例

[`insecure/exceptions/broad-scope.yaml`](insecure/exceptions/broad-scope.yaml) は、
`target_id: "*"`、`environment: all`、ownerによる自己承認、短いrisk記述、policyを
超える期間を持ちます。[`insecure/exceptions/expired.yaml`](insecure/exceptions/expired.yaml)
は形式が正しくても評価日時点で期限切れです。どちらもsecurity gateを通りません。

## 安全な例

[`secure/exceptions/active-dependency.yaml`](secure/exceptions/active-dependency.yaml) と
[`secure/exceptions/expiring-scanner.yaml`](secure/exceptions/expiring-scanner.yaml) は、実在する
control/checkの組、syntheticなexact target、異なるowner・risk reviewer・approver、
代替control、承認ticket、是正ticket、最大30日以内の期限を持ちます。

[`secure/register.json`](secure/register.json) は取得成否、完全性、観測時刻、全YAMLの
SHA-256を宣言します。例外YAMLを消す、台帳外ファイルを足す、内容だけ変える場合は
decisionを続行せず`ERROR`になります。

## 実行と期待結果

```bash
make verify-control CONTROL=PSB-GOV-002
```

直接実行する場合:

```bash
python3 controls/governance-operations/time-bound-security-exceptions/scripts/verify.py \
  --policy controls/governance-operations/time-bound-security-exceptions/secure/policy.yaml \
  --register controls/governance-operations/time-bound-security-exceptions/secure/register.json \
  --exceptions-dir controls/governance-operations/time-bound-security-exceptions/secure/exceptions \
  --evaluation-time 2026-08-05T10:10:00Z
```

期待される概要:

```text
ACTIVE EXC-2026-0001 control=PSB-DEPS-001 check=COOL-003 expires_at=2026-08-25T09:00:00Z
EXPIRING EXC-2026-0002 control=PSB-DETECT-001 check=DVS-006 expires_at=2026-08-10T10:00:00Z
PASS PSB-GOV-002 exception register accepted: active=1 expiring=1 expired=0 invalid=0
```

終了コードは`0=利用可能な台帳`、`1=期限切れまたはpolicy不適合`、`2=証跡・取得・解析
ERROR`です。`2`を「例外なし」や「問題なし」へ変換してはいけません。

## 他controlへの統合方法

各controlは次の順で統合します。

1. 自controlの`control_id`と対象`check_id`を指定する。
2. 適用対象を`target_type`、一意な`target_id`、`environment`へ正規化する。
3. このverifierまたは同じ契約を使う中央serviceから`ACTIVE`／`EXPIRING`だけを受け取る。
4. 例外が有効でもcontrol本体を`PASS`へ書き換えず、例外適用を別decisionとして記録する。
5. `EXPIRED`、`INVALID`、`ERROR`は元のsecurity failureを解除しない。

既存control内のJSON例外は一度に削除しません。移行時にはcontrol固有fieldを共通YAMLへ
変換する薄いadapterを置き、同じ意味を二つのschemaで管理しないよう段階的に切り替えます。
`PSB-GOV-002`は例外のlifecycleを所有し、scanner findingやdependency cooldownなどの
control固有risk判定は元controlが所有します。

## 証跡の安全性

YAMLは固定fieldだけを許可し、credential、token、secret、private key、request/response
body、source code、payloadを表すfieldを拒否します。代表的なcredential文字列も値を
出力せず`ERROR`にします。ticketには実payloadを複製せず、参照IDだけを記録してください。

fixtureのID、package、CVE、digest、team、ticketはすべてsyntheticであり、実secret、
個人情報、production dataを含みません。

## 運用上の制限

- SHA-256は内容の不一致を検出しますが、署名ではありません。productionでは承認systemの
  immutable audit log、branch protection、署名付きdecision receipt等と結合してください。
- `--evaluation-time`は再現可能なfixture用です。production adapterは信頼できるUTC時刻を
  注入し、利用者が過去時刻を自由指定できないようにしてください。
- `EXPIRING`は警告であり、このreferenceは通知やticket更新を実行しません。
- 最大30日はreference policyです。組織はrisk classに応じて短くできますが、長期化は
  policy reviewなしに許可しないでください。
- 一件の例外が適切でも、組織全体のrisk acceptance processやframework準拠を証明しません。
- 既存control固有例外の移行が終わるまでは、重複台帳とsemantic driftを監視する必要があります。

## 関連資料

- [Repository security exception policy](../../../policies/exceptions/README.md)
- [Control model](../../../docs/CONTROL_MODEL.md)
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OpenSSF Security Baseline 2026-02-19](https://baseline.openssf.org/versions/2026-02-19)
