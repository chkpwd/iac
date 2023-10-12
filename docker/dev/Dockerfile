ARG BASE_IMAGE_TAG=23.04

FROM ubuntu:${BASE_IMAGE_TAG}

USER root

ENV DEBIAN_FRONTEND=noninteractive

ENV DEV=ubuntu

# Base System Configuration
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Core Utilities
    bash curl sudo man-db bash-completion wget unzip \
    less locales ca-certificates gnupg apt-transport-https \
    # Development Tools
    build-essential file pwgen git vim htop jq yq ldap-utils \
    rsync rclone software-properties-common pkg-config \
    libxmlsec1-dev golang-go npm nodejs upx-ucl \
    # SSH Tools
    openssh-server openssh-client sshpass \
    # Network Tools
    nmap mtr-tiny host net-tools iputils-ping traceroute dnsutils ipcalc \
    # Disk Utilities
    genisoimage \
    # Text Processing and Viewing
    bat fzf tree \
    # Python Tools
    pipx python3-dev python3-pip python3-venv python3-setuptools \
    # Zsh and Plugins
    zsh zsh-autosuggestions zsh-syntax-highlighting \
    # Miscellaneous Tools
    direnv age hugo && \
    # SSH Config
    ssh-keygen -A && \
    mkdir -p /run/sshd && \
    # Elavation Setup
    echo "%sudo ALL = (ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    # Locale Setup
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen && \
    # Perform clean-up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# renovate: datasource=github-tags depName=BeryJu/korb
ARG KORB_VERSION=v2.2.0

# renovate: datasource=github-tags depName=atuinsh/atuin
ARG ATUIN_VERSION=16.0.0

# renovate: datasource=github-tags depName=helm/helm
ARG HELM_VERSION=v3.13.0

# renovate: datasource=github-tags depName=bitwarden/sdk
ARG BWS_SDK_VERSION=0.3.0

# renovate: datasource=github-tags depName=knqyf263/pet
ARG PET_VERSION=0.5.0

# renovate: datasource=github-tags depName=tellerops/teller
ARG TELLER_VERSION=1.5.6

# renovate: datasource=github-tags depName=twpayne/chezmoi
ARG CHEZMOI_VERSION=v2.40.2

# renovate: datasource=github-tags depName=kubernetes/kubernetes
ARG KUBECTL_VERSION=1.28.2

# renovate: datasource=github-tags depName=stern/stern
ARG STERN_VERSION=1.26.0

# renovate: datasource=github-tags depName=kubernetes-sigs/krew
ARG KREW_VERSION=0.4.4

# renovate: datasource=github-tags depName=sachaos/viddy
ARG VIDDY_VERSION=0.3.7

# renovate: datasource=github-tags depName=derailed/k9s
ARG K9S_VERSION=0.27.4

# renovate: datasource=github-tags depName=pulumi/pulumi
ARG PULUMI_VERSION=v3.88.0

# renovate: datasource=github-tags depName=hashicorp/terraform
ARG TERRAFORM_VERSION=v1.6.1

# renovate: datasource=github-tags depName=getsops/sops
ARG SOPS_VERSION=3.8.0

# renovate: datasource=github-tags depName=bitwarden/clients
ARG BW_CLI_VERSION=2023.8.2

# renovate: datasource=github-tags depName=loft-sh/vcluster
ARG VCLUSTER_VERSION=v0.16.3

# renovate: datasource=github-tags depName=FairwindsOps/nova
ARG NOVA_VERSION=3.7.0

# renovate: datasource=github-tags depName=FairwindsOps/pluto
ARG PLUTO_VERSION=5.18.4

# Download and Install Various Tools
RUN \
    # Download and install Korb
    curl -L "https://github.com/BeryJu/korb/releases/download/{KORB_VERSION}/korb_linux_amd64" -o /tmp/korb && \
    mv /tmp/korb /usr/bin/korb && \
    # Download and install Atuin
    curl -L "https://github.com/atuinsh/atuin/releases/download/v${ATUIN_VERSION}/atuin-v${ATUIN_VERSION}-x86_64-unknown-linux-gnu.tar.gz" | tar xvzf - -C /tmp --strip-components=1 && \
    mv /tmp/atuin /usr/bin/atuin && \
    # Download and install Helm
    curl "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" | tar xvzf - -C /tmp --strip-components=1 && \
    mv /tmp/helm /usr/bin/helm && \
    chmod +x /usr/bin/helm && \
    # Download and install sops
    curl -L "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops_${SOPS_VERSION}_amd64.deb" > /tmp/sops_amd64.deb && \
    dpkg -i /tmp/sops_amd64.deb && \
    # Download and install BW-CLI
    curl -L "https://github.com/bitwarden/clients/releases/download/cli-v${BW_CLI_VERSION}/bw-linux-${BW_CLI_VERSION}.zip" -o /tmp/bw.zip && \
    unzip /tmp/bw.zip -d /tmp && \
    mv /tmp/bw /usr/bin/bw && \
    chmod +x /usr/bin/bw && \
    # Download and install stern
    curl -L "https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_amd64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/stern /usr/bin/stern && \
    chmod +x /usr/bin/stern && \
    # Download and install bws-sdk
    curl -L "https://github.com/bitwarden/sdk/releases/download/bws-v${BWS_SDK_VERSION}/bws-x86_64-unknown-linux-gnu-${BWS_SDK_VERSION}.zip" > /tmp/bws.zip && \
    unzip /tmp/bws.zip -d /tmp && \
    mv /tmp/bws /usr/bin/ && \
    # Download and install pulumi
    curl -L "https://get.pulumi.com/releases/sdk/pulumi-${PULUMI_VERSION}-linux-x64.tar.gz" | tar xvzf - -C /tmp --strip-components=1 && \
    mv /tmp/pulumi* /usr/bin/ && \
    # Download and install terraform
    curl -LO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION#v}/terraform_${TERRAFORM_VERSION#v}_linux_amd64.zip" && \
    unzip "terraform_${TERRAFORM_VERSION#v}_linux_amd64.zip" -d /tmp && \
    mv /tmp/terraform /usr/bin/terraform && \
    # Download and install Pet Snippet
    curl -L "https://github.com/knqyf263/pet/releases/download/v${PET_VERSION}/pet_${PET_VERSION}_linux_amd64.deb" > pet.deb && \
    dpkg -i pet.deb && \
    rm -f pet.deb && \
    # Download and install Teller
    curl -L "https://github.com/tellerops/teller/releases/download/v${TELLER_VERSION}/teller_${TELLER_VERSION}_Linux_x86_64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/teller /usr/bin/teller && \
    # Download and install chezmoi
    curl -L "https://github.com/twpayne/chezmoi/releases/download/${CHEZMOI_VERSION}/chezmoi_${CHEZMOI_VERSION#v}_linux_amd64.deb" > chezmoi.deb && \
    dpkg -i chezmoi.deb && \
    rm -f chezmoi.deb && \
    # Download and install kubectl
    curl -LO "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv ./kubectl /usr/bin/kubectl && \
    # Download and install krew
    curl -L "https://github.com/kubernetes-sigs/krew/releases/download/v${KREW_VERSION}/krew-linux_amd64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/krew-linux_amd64 /usr/bin/krew && \
    krew install virt ctx ns && \
    # Download and install viddy
    curl -L "https://github.com/sachaos/viddy/releases/download/v${VIDDY_VERSION}/viddy_Linux_x86_64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/viddy /usr/bin/viddy && \
    # Download and install k9s
    curl -L "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_amd64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/k9s /usr/bin/k9s && \
    # Download and install vCluster
    curl -L "https://github.com/loft-sh/vcluster/releases/download/v${VCLUSTER_VERSION}/vcluster-linux-amd64" -o vcluster && \
    chmod +x vcluster && \
    mv ./vcluster /usr/bin/vcluster && \
    # Download and install Nova
    curl -L "https://github.com/FairwindsOps/nova/releases/download/v${NOVA_VERSION}/nova_${NOVA_VERSION}_linux_amd64.tar.gz" > /tmp/nova.tar.gz && \
    tar -xvf /tmp/nova.tar.gz -C /tmp/ && \
    mv /tmp/nova /usr/bin/nova && \
    # Download and install Pluto
    curl -L "https://github.com/FairwindsOps/pluto/releases/download/${PLUTO_VERSION}/pluto_${PLUTO_VERSION#v}_linux_amd64.tar.gz" > /tmp/pluto.tar.gz && \
    tar -xvf /tmp/pluto.tar.gz -C /tmp/ && \
    mv /tmp/pluto /usr/bin/pluto && \
    # Docker Install
    apt-get update && \
    apt-get install -y ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-buildx-plugin \
    docker-compose-plugin

RUN bash -c "rm -rf /tmp/*"

# Copy Commands for Various Tools
COPY --from=docker.io/istio/istioctl:1.19.2 /usr/local/bin/istioctl /usr/bin/istioctl
COPY --from=docker.io/fluxcd/flux-cli:v2.1.1 /usr/local/bin/flux /usr/bin/flux
COPY --from=docker.io/klakegg/hugo:0.111.3-ext-ubuntu /usr/lib/hugo/hugo /usr/bin/hugo
COPY --from=gcr.io/kaniko-project/executor:v1.16.0 /kaniko/executor /usr/bin/kaniko
COPY --from=quay.io/coreos/etcd:v3.5.9 /usr/local/bin/etcdctl /usr/bin/etcdctl
COPY --from=docker.io/hashicorp/packer:light-1.9.4 /bin/packer /usr/bin/packer
COPY --from=docker.io/digitalocean/doctl:1.99.0 /app/doctl /usr/bin/doctl
COPY --from=docker.io/vmware/govc:v0.32.0 /govc /usr/bin/govc

# UPX all of the binaries
RUN for item in bw bws nova pluto terraform pulumi pet teller chezmoi \
    kubectl stern krew viddy k9s helm sops vcluster \
    pluto curl istioctl flux hugo kaniko \
    etcdctl doctl govc packer; do \
    upx $(which $item); \
    done

# User Config
RUN su -c "ssh-keygen -t ed25519 -b 2048 -f /home/$DEV/.ssh/id_ed25519 -qN ''" $DEV && \
    passwd -d $DEV

# User Setup
USER $DEV

# Python
RUN \
    pipx install poetry && \
    # Ansible Modules
    pipx install ansible-base ansible-lint && \
    pipx install molecule

# Set ZSH Custom Dir
ENV ZSH_CUSTOM=/home/$DEV/.oh-my-zsh/custom

# ZSH Setup
RUN \
    # Install ZSH
    curl -L https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh > /tmp/install.sh && \
    chmod +x /tmp/install.sh && \
    yes | ./tmp/install.sh && \
    rm /tmp/install.sh && \
    echo $ZSH_CUSTOM && \
    mkdir -p $ZSH_CUSTOM/completions && \
    chmod -R 755 $ZSH_CUSTOM/completions && \
    curl -L https://gist.githubusercontent.com/raw/88d7f239615905dcad6b74e8e4b0fbbf -o $HOME/.zshrc && \
    curl -L https://raw.githubusercontent.com/agkozak/zsh-z/master/zsh-z.plugin.zsh > $ZSH_CUSTOM/plugins/zsh-z && \
    # Auto Complete for Tools
    helm completion zsh > $ZSH_CUSTOM/completions/helm.zsh && \
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/completion/_kubectx.zsh > $ZSH_CUSTOM/completions/_kubectx.zsh && \
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/completion/_kubens.zsh > $ZSH_CUSTOM/completions/_kubens.zsh && \
    flux completion zsh > $ZSH_CUSTOM/completions/flux.zsh && \
    hugo completion zsh > $ZSH_CUSTOM/completions/hugo.zsh && \
    echo 'autoload -U bashcompinit && \
    bashcompinit && \
    eval "$(register-python-argcomplete pipx)"' > $ZSH_CUSTOM/completions/pipx.zsh

# Bitwarden CLI Configuration
ENV BW_API_KEY=
ENV BW_EMAIL_ADDRESS=
ENV BW_PASSWORD=
ENV GIT_USER=
ENV PULL_REPOS=

# Copy files into the image
COPY ./app/setup_env.sh /setup_env.sh

# By default, run a shell if no other command is provided to docker run
CMD ["/bin/zsh"]
