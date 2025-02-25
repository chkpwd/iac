# Infrastructure as Code (IaC) by Bryan J.

## General Overview

This repository provides a set of tools and configurations for automating tasks across environments, including Ansible playbooks and roles, Docker configurations, Kubernetes manifests, Terraform modules, and Packer scripts, with secrets managed through SOPs integration. I tried not to be opinionated in the way I tackle issues.

### Live Infrastructure Stats:
<div align="left">
Kubernetes:

[![Kubernetes](https://img.shields.io/endpoint?url=https%3A%2F%2Fkromgo.chkpwd.com%2Fkubernetes_version&style=flat-square&logo=kubernetes&logoColor=white&color=blue&label=k8s)](https://kubernetes.io)&nbsp;&nbsp;

[![Flux](https://img.shields.io/endpoint?url=https%3A%2F%2Fkromgo.chkpwd.com%2Fflux_version&style=for-the-badge&logo=flat-square&logoColor=white&color=blue&label=flux)](https://fluxcd.io)
</div>

```
~/code/iac main*
❯ curl -s "https://cluster-stats:8080" | jq -r '.[] | "\(.metric): \(.value)"'

  Metric          | Value
  ----------------|--------
  Nodes Count     | 3
  Cluster Age     | 285 days
  Cluster Uptime  | 52.7 days
  Number of Pods  | 130
  Memory Usage    | 34.3%
  CPU Usage       | 29.6%
  Network Usage   | 0.6MB/s

  Time Checked: 2025-02-25-22:13:28
```
