# Security効果はEnforcement Pointに宿る

## Insight

Security Artifactの価値は、そのArtifactが存在することではなく、保護対象へのoperationを実際に変える
Enforcement Pointへ接続されることから生まれます。

```text
guidance / policy / configuration / decision
                    |
                    v
             Enforcement Point
                    |
          allow / deny / restrict / stop
                    |
                    v
             protected operation
```

## 二つの具体例

Credential policy JSONに「PATは短命」と書いても、source platform上のgrantとexpiryは変わりません。
効果が生まれるのは、provider／IdPのauthentication、repository permission、expiry、revocationが
実requestへ強制されたときです。

`.npmrc` sampleにminimum ageを書いても、developer、bot、CIが別のresolver設定を使えばyoung releaseは
採用されます。効果が生まれるのは、実resolverまたはtrusted CIがdependency code実行前にcandidateを止めるときです。

## 設計reviewへの応用

1. 守りたいoperationを動詞で書く。例：sourceを変更する、packageをresolveする。
2. 最終的にoperationを実行するcomponentを特定する。
3. Allow／denyを決めるauthorityと、decision inputの信頼元を特定する。
4. Alternate path、fallback、admin path、cached decisionを追う。
5. Artifactのtestと、live Enforcement Pointのtestを区別する。

## よくある誤用

- Policy repositoryにfileがあるため導入済みとする。
- Sample verifierの`PASS`をproduction settingの`PASS`へ昇格する。
- Scannerの実行失敗をfindingなしとして扱う。
- Guidance-first Controlを無理にfixture化し、実境界を観測しない。

## 限界

Enforcement Pointが存在しても、policy semantics、identity、resource resolutionが誤っていれば安全とは限りません。
このInsightは「どこを見るか」を示すもので、個別Controlの正しいdecisionを定義するものではありません。

## Related artifacts

- [PSB-SOURCE-004](../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md)
- [PSB-DEPS-001](../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md)
- [Source credential Engineering Pattern](../../engineering/source-protection/source-access-credential-lifecycle/README.md)
- [Dependency cooldown Engineering Pattern](../../engineering/dependency-security/dependency-release-cooldown/README.md)
