# Infrastructure as Code (IaC) by Bryan J.

A repository dedicated to **Infrastructure as Code (IaC)**. This repository is a testament to Bryan's passion for technology, encompassing everything from hardware and software to automation.

## General Overview

This repository is a collection of tools, scripts, and configurations that demonstrate the power of automation in managing and provisioning infrastructure. I tried not to be opinionated in the way I tackle issues. In general it includes various components such as:

### 🧰 Ansible

#### Playbooks and Roles
A comprehensive set of playbooks and roles for automating tasks across different environments. Powered by a dynamic inventory whenever possible.
###### Note: Secrets are managed through SOPs ansible integration. 

### 🐳 Docker

#### Configurations
Containerized applications and services, including custom Nginx configurations.

### ☸️ Kubernetes

#### Manifests
A wide range of Kubernetes applications, tools, and core components. **Flux** is installed via **Ansible**.
###### Note: Secrets are managed through SOPs ansible integration.

### 🏗️ Terraform

#### Modules
Infrastructure provisioning using Terraform for different cloud providers and platforms. The state file is managed and stored in [Terraform Cloud](https://app.terraform.io/app).

###### Note: Secrets are managed through SOPs ansible integration. 

### 📦 Packer

#### Scripts
Automated machine image creation for different operating systems.
###### Example:  
```bash
packer build -force --only vsphere-iso.windows --var-file=windows/22H2-W11.pkrvars.hcl -var "vcenter_password=$VCENTER_PASS" .
```
###### Note: The VCENTER_PASS var gets passed at runtime using [.envrc](https://github.com/chkpwd/iac/blob/main/packer/.envrc) in the packer directory.

### 🛠️ Vagrant

#### Files
Development environments using Vagrant for both Hyper-V and KVM. Additionally, for **Ansible Molecule** testing, it uses **Docker** as the driver.

## 🚀 Getting Started

To get started with this repository, you may explore the different directories to find the specific tools or configurations you need. Each directory typically contains detailed instructions or scripts to help you set up and run the components.

## 🤝 Contributions

Feel free to contribute to this repository by submitting pull requests or opening issues. Check the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on contributing.

## 📜 License

This project is licensed under the terms of the [LICENSE](LICENSE) file.

## 📧 Contact

For any questions or feedback, please reach out to Bryan Jones through GitHub.
