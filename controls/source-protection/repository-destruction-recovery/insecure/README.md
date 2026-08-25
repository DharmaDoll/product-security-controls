# Insecure implementation

次の構成はcritical repositoryの独立復旧を提供しません。

- repository adminを含む多数のmemberがrepositoryを削除・移管できる。
- default branchやrelease tagをadminが制限なく削除またはforce pushできる。
- backupが同じGitHub Organizationのforkまたはmirrorだけである。
- GitHub Organization Ownerがbackup storageも管理し、backup objectを削除できる。
- backup writerがretention変更、object削除、storage policy変更の権限を持つ。
- default branchの通常cloneだけを保存し、他branch、tag、LFSを確認しない。
- backup jobの成功logだけを確認し、隔離restoreを実施しない。

この構成では、一つの侵害authorityまたは操作ミスがsourceとrecovery copyを同時に破壊できます。
