ARG BASE_IMAGE_TAG=23.04

FROM ubuntu:${BASE_IMAGE_TAG}

USER root

ENV DEBIAN_FRONTEND=noninteractive

ENV DEV=ubuntu

# renovate: datasource=github-tags depName=bitwarden/sdk
ARG BWS_SDK_VERSION=0.3.0

# renovate: datasource=github-tags depName=knqyf263/pet
ARG PET_VERSION=0.5.0

# renovate: datasource=github-tags depName=tellerops/teller
ARG TELLER_VERSION=1.5.6

# renovate: datasource=github-tags depName=twpayne/chezmoi
ARG CHEZMOI_VERSION=2.39.1

# renovate: datasource=github-tags depName=kubernetes/kubernetes
ARG KUBECTL_VERSION=1.28.1

# renovate: datasource=github-tags depName=stern/stern
ARG STERN_VERSION=1.26.0

# renovate: datasource=github-tags depName=kubernetes-sigs/krew
ARG KREW_VERSION=0.4.4

# renovate: datasource=github-tags depName=sachaos/viddy
ARG VIDDY_VERSION=0.3.7

# renovate: datasource=github-tags depName=derailed/k9s
ARG K9S_VERSION=0.27.4

# renovate: datasource=github-tags depName=pulumi/pulumi
ARG PULUMI_VERSION=v3.82.1

# renovate: datasource=github-tags depName=hashicorp/terraform
ARG TERRAFORM_VERSION=1.5.7

# renovate: datasource=github-tags depName=getsops/sops
ARG SOPS_VERSION=3.7.3

# renovate: datasource=github-tags depName=bitwarden/clients
ARG BW_CLI_VERSION=2023.8.4

# renovate: datasource=github-tags depName=loft-sh/vcluster
ARG VCLUSTER_VERSION=0.15.7

# renovate: datasource=github-tags depName=FairwindsOps/nova
ARG NOVA_VERSION=3.7.0

# renovate: datasource=github-tags depName=FairwindsOps/pluto
ARG PLUTO_VERSION=5.18.4

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
    nmap mtr-tiny host net-tools iputils-ping traceroute dnsutils \
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

# Download and Install Various Tools
RUN \
    # Determine the Platform Architecture
    export PLATFORM=$(dpkg --print-architecture) && \
    # Download and install bws-sdk
    curl -L "https://github.com/bitwarden/sdk/releases/download/bws-v${BWS_SDK_VERSION}/bws-x86_64-unknown-linux-gnu-${BWS_SDK_VERSION}.zip" > /tmp/bws.zip && \
    unzip /tmp/bws.zip && \
    mv bws /usr/bin/ && \
    # Download and install pulumi
    if [ "$PLATFORM" = "amd64" ]; then \
    curl -L "https://get.pulumi.com/releases/sdk/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" | tar xvzf - -C /tmp --strip-components=1; \
    elif [ "$PLATFORM" = "arm64" ]; then \
    curl -L "https://get.pulumi.com/releases/sdk/pulumi-v${PULUMI_VERSION}-linux-${PLATFORM}.tar.gz" | tar xvzf - -C /tmp --strip-components=1; \
    fi && \
    mv /tmp/pulumi* /usr/bin/ && \
    # Download and install terraform
    curl -LO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${PLATFORM}.zip" && \
    unzip "terraform_${TERRAFORM_VERSION}_linux_${PLATFORM}.zip" && \
    mv terraform /usr/bin/terraform && \
    rm "terraform_${TERRAFORM_VERSION}_linux_${PLATFORM}.zip" && \
    # Download and install Pet Snippet
    curl -L "https://github.com/knqyf263/pet/releases/download/v${PET_VERSION}/pet_${PET_VERSION}_linux_${PLATFORM}.deb" > pet.deb && \
    dpkg -i pet.deb && \
    rm -f pet.deb && \
    # Download and install Teller
    curl -L "https://github.com/tellerops/teller/releases/download/v${TELLER_VERSION}/teller_${TELLER_VERSION}_Linux_x86_64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/teller /usr/bin/teller && \
    # Download and install chezmoi
    curl -L "https://github.com/twpayne/chezmoi/releases/download/v${CHEZMOI_VERSION}/chezmoi_${CHEZMOI_VERSION}_linux_${PLATFORM}.deb" > chezmoi.deb && \
    dpkg -i chezmoi.deb && \
    rm -f chezmoi.deb && \
    # Download and install kubectl
    curl -LO "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${PLATFORM}/kubectl" && \
    chmod +x kubectl && \
    mv ./kubectl /usr/bin/kubectl && \
    # Download and install stern
    curl -L "https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_${PLATFORM}.tar.gz" | tar xvzf - --strip-components=1 && \
    mv stern /usr/bin/stern && \
    chmod +x /usr/bin/stern && \
    # Download and install krew
    curl -L "https://github.com/kubernetes-sigs/krew/releases/download/v${KREW_VERSION}/krew-linux_${PLATFORM}.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/krew-linux_${PLATFORM} /usr/bin/krew && \
    # Install Virt ONLY if we're on amd64
    if [ "$PLATFORM" = "amd64" ]; then krew install virt; fi && \
    # Download and install viddy
    curl -L "https://github.com/sachaos/viddy/releases/download/v${VIDDY_VERSION}/viddy_${VIDDY_VERSION}_Linux_x86_64.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/viddy /usr/bin/viddy && \
    # Download and install k9s
    curl -L "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_${PLATFORM}.tar.gz" | tar xvzf - -C /tmp && \
    mv /tmp/k9s /usr/bin/k9s && \
    # Download and install helm
    curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash && \
    # Download and install sops
    curl -L "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops_${SOPS_VERSION}_${PLATFORM}.deb" > /tmp/sops_${PLATFORM}.deb && \
    dpkg -i /tmp/sops_${PLATFORM}.deb && \
    # Download and install BW-CLI
    curl -L "https://github.com/bitwarden/clients/releases/download/cli-v${BW_CLI_VERSION}/bw-linux-${BW_CLI_VERSION}.zip" -o /tmp/bw.zip && \
    unzip /tmp/bw.zip -d /tmp && \
    chmod +x /tmp/bw && \
    mv /tmp/bw /usr/bin/bw && \
    # Download and install vCluster
    curl -L "https://github.com/loft-sh/vcluster/releases/download/v${VCLUSTER_VERSION}/vcluster-linux-${PLATFORM}" -o vcluster && \
    chmod +x vcluster && \
    mv ./vcluster /usr/bin/vcluster && \
    # Download and install Nova
    curl -L "https://github.com/FairwindsOps/nova/releases/download/${NOVA_VERSION}/nova_${NOVA_VERSION}_linux_${PLATFORM}.tar.gz" > /tmp/nova.tar.gz && \
    tar -xvf /tmp/nova.tar.gz -C /tmp/ && \
    mv /tmp/nova /usr/bin/nova && \
    # Download and install Pluto
    curl -L "https://github.com/FairwindsOps/pluto/releases/download/v${PLUTO_VERSION}/pluto_${PLUTO_VERSION}_linux_${PLATFORM}.tar.gz" > /tmp/pluto.tar.gz && \
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
    docker-compose-plugin1

RUN bash -c "rm -rf /tmp/*"

# Copy Commands for Various Tools
COPY --from=docker.io/istio/istioctl:1.19.0 /usr/local/bin/istioctl /usr/bin/istioctl
COPY --from=docker.io/fluxcd/flux-cli:v2.1.0 /usr/local/bin/flux /usr/bin/flux
COPY --from=docker.io/klakegg/hugo:0.111.3-ext-ubuntu /usr/lib/hugo/hugo /usr/bin/hugo
COPY --from=gcr.io/kaniko-project/executor:v1.15.0 /kaniko/executor /usr/bin/kaniko
COPY --from=quay.io/coreos/etcd:v3.5.9 /usr/local/bin/etcdctl /usr/bin/etcdctl

# Copy Commands, but these only work on amd64 architecture
COPY --from=docker.io/digitalocean/doctl:1.98.1 /app/doctl /usr/bin/doctl
COPY --from=docker.io/vmware/govc:v0.30.7 /govc /usr/bin/govc

# UPX all of the binaries
RUN for item in bw bws nova pluto terraform pulumi pet teller chezmoi \
    kubectl stern krew viddy k9s helm sops vcluster \
    pluto curl istioctl flux hugo kaniko \
    etcdctl doctl govc; do \
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
    pipx install ansible-base && \
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
ENV BW_EMAIL_ADDRESS=
ENV BW_PASSWORD=
ENV GIT_USER=

# Copy files into the image
COPY ./app/setup_env.sh /setup_env.sh

# By default, run a shell if no other command is provided to docker run
CMD ["/bin/zsh"]
