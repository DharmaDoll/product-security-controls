# Credentialは文字列ではなく委任されたauthority

## Insight

Credential securityを「秘密値を漏らさないこと」だけで評価すると、overprivilege、長いlifetime、
広いconsumer scope、失効漏れを見落とします。Credentialは、providerが受け入れる委任されたauthorityです。

```text
credential
  = identity proof or grant
  + reachable resources
  + permitted operations
  + validity period
  + accepted consumers and sessions
```

## 具体例

同じprotected storeに保存された二つのtokenでも、一方が一つのrepositoryへのreadだけ、もう一方が
organization全体へのwriteを許可するなら、窃取時のriskは同じではありません。

逆に、短命tokenでも親IDE全体へ渡し、すべてのextensionが取得できるなら、consumer boundaryは広いままです。

## 設計reviewへの応用

- Secret scannerの有無だけでなく、active grant inventoryを見る。
- Token typeのlabelではなく、resource、permission、expiryを確認する。
- Humanとworkloadのidentityを分ける。
- Storageとprocess deliveryを分けてdiagram化する。
- Rotation、expiry、revocation、session invalidationを別の状態として追う。
- Audit eventとcurrent authorityを同じ証拠として扱わない。

## 他領域への適用

この見方はsource tokenだけでなく、cloud credential、registry token、signing authority、MCP credential、
database connection、temporary approvalにも使えます。

## 限界

Authorityを狭めてもcredential theft自体は防ぎ切れません。Endpoint、phishing-resistant authentication、
runtime isolation、detection、incident responseを組み合わせます。

## Related artifacts

- [PSB-SOURCE-004 Control](../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md)
- [Source access credential lifecycle Learning](../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/learning.md)
- [Source access credential lifecycle Pattern](../../engineering/source-protection/source-access-credential-lifecycle/README.md)
