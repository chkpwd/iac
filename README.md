# Infrastructure as Code (IaC) by Bryan J.

## General Overview

This repository provides a set of tools and configurations for automating tasks across environments, including Ansible playbooks and roles, Docker configurations, Kubernetes manifests, Terraform modules, and Packer scripts, with secrets managed through SOPs integration. I tried not to be opinionated in the way I tackle issues.

### Live Infrastructure Stats:
<div align="left">
Kubernetes:

```
~/code/iac main*
❯ curl -s "https://cluster-stats:8080" | jq -r '.[] | "\(.metric): \(.value)"'

  Kubernetes: v1.31.3+k3s1
  Flux Version: No Data

  Metric          | Value
  ----------------|--------
  Nodes Count     | 3
  Cluster Age     | 285 days
  Cluster Uptime  | 52.7 days
  Number of Pods  | 130
  Memory Usage    | 34.9%
  CPU Usage       | 32.1%
  Network Usage   | 0.7MB/s

  Last updated: 2025-02-25-22:27:37
```

```
~/code/iac main*
❯ curl -s "https://cluster-stats:8080" | jq -r '.[] | "\(.metric): \(.value)"'

  Kubernetes: v1.31.3+k3s1
  Flux Version: No Data

  Metric          | Value
  ----------------|--------
  Nodes Count     | 3
  Cluster Age     | 285 days
  Cluster Uptime  | 52.7 days
  Number of Pods  | 130
  Memory Usage    | 34.2%
  CPU Usage       | 27.9%
  Network Usage   | 0.7MB/s

  Last updated: 2025-02-25-23:05:45
```
