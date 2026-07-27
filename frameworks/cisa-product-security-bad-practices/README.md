# CISA Product Security Bad Practices Registry

CISA/FBIのProduct Security Bad Practicesは、software manufacturerが避けるべき
特に危険なproduct property、security feature、organizational processを
ネガティブ基準として使用します。

## 固定ベースライン

- Document: Product Security Bad Practices
- Version: `2`
- Publication: `January 2025`
- Official PDF SHA-256:
  `c0431ac502e8bcf5ae2e4f2f47249a2aae6ead00e0af6542bd29adac850a9d3e`
- Machine-readable registry: [`registry.json`](registry.json)

公式文書は13項目へ通し番号を付けていますが、framework-styleの永続IDは
公開していません。このレジストリは次の規則でlocal stable IDを割り当てます。

- `CISA-PSBP-PP-01`から`08`: Product Properties
- `CISA-PSBP-SF-09`から`10`: Security Features
- `CISA-PSBP-OP-11`から`13`: Organizational Processes and Policies

version更新時は番号だけで同一性を判断せず、各項目の意味を再レビューします。

## マッピング境界

このguidanceはcritical infrastructureやNational Critical Functionsを主対象とする
voluntary guidanceです。本PJでは適用範囲を不当に一般化せず、controlが同じ
bad practiceを直接防止または検出するときだけ`mitigates`、`detects`、
`supports`を使用します。

マッピングはCISA推奨事項の完全実装、製品全体のSecure by Design達成、
規制適合を意味しません。insecure fixtureでbad practiceを再現する場合も、
隔離されたsynthetic exampleだけを使用します。
