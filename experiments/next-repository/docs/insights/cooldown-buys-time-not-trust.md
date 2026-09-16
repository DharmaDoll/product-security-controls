# Cooldownはtrustではなく観測時間を買う

## Insight

Dependency cooldownは、一定時間後のartifactを信頼済みに変えるControlではありません。
公開直後には不足している外部signalが現れるための時間を確保するControlです。

```text
publish
   |
   |  information-poor window
   |  detection / reports / yank / advisory may emerge
   v
reviewed observation boundary
```

## なぜ区別が必要か

「7日経過＝安全」と扱うと、長期潜伏malware、typosquatting、compromised registry、artifact substitutionを
見落とします。一方で、時間はpackage内容を保証しなくても、公開直後の自動採用を避ける独立した価値があります。

## 設計reviewへの応用

- 何時間待つかだけでなく、何のsignalを待つのかを言語化する。
- Publish timestampのauthorityを確認する。
- Cooldownをcode実行より前に置く。
- Scanner、proxy reputation、lockfile、integrityと保証を分ける。
- Emergency fixでは、global ruleを弱めずexact versionだけを期限付きで扱う。

## 他領域への適用

同じMental Modelは、新しいcontainer image、tool plugin、AI model、agent Skill、browser extension、
GitHub Action等の公開直後riskにも応用できます。ただし各Artifactで信頼するpublish identityと
実行境界を定義する必要があります。

## 限界

Observation windowの長さに普遍的な正解はありません。更新速度、active exploitation、signal quality、
代替Controlを踏まえて決めます。時間だけをformal trustへ変換しません。

## Related artifacts

- [PSB-DEPS-001 Control](../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md)
- [Dependency release cooldown Learning](../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/learning.md)
- [Dependency release cooldown Pattern](../../engineering/dependency-security/dependency-release-cooldown/README.md)
