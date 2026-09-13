# Insecure example: persistent self-hosted runner

[persistent-self-hosted.yml](persistent-self-hosted.yml) is deliberately insecure. It shows the
failure mode this control is intended to prevent:

- untrusted pull-request code is sent to a generic `self-hosted` label;
- a long-lived machine can receive multiple jobs;
- the job can inherit host, metadata, runtime-socket, and management-network reachability;
- local workspace cleanup is mistaken for destruction of the underlying compute;
- logs disappear with the runner.

Do not copy or enable this workflow. It has no automatic trigger so that it cannot be deployed by
accident. The secure alternatives are listed in the [control README](../README.md#最短の導入手順).
