# 隔離されたinsecure fixture

このdirectoryは、未信頼PRを長寿命self-hosted runnerで処理し、mutable image、
prior-job state、host credential、cloud metadata、management network、runtime socket、
SSH ingress、runner再利用、teardownと外部logの欠落を意図的に含むnegative testです。

実runnerとして登録またはdeploymentしてはいけません。credential fieldは含まず、
観測結果をbooleanで表したsynthetic dataだけを使用します。
