ARG BASE_IMAGE_TAG=23.10

FROM ubuntu:${BASE_IMAGE_TAG}

USER root

ENV DEBIAN_FRONTEND=noninteractive

ENV DEV=chk

# Base System Configuration
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
		# Core Utilities
        bash curl sudo man-db bash-completion wget unzip less locales gnupg apt-transport-https \
        # Development Tools
        build-essential file pwgen git vim htop jq yq ldap-utils rsync tmate rclone software-properties-common \
        pkg-config libxmlsec1-dev golang-go npm nodejs \
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
# Pet Snippet
	curl -L https://github.com/knqyf263/pet/releases/download/v0.5.0/pet_0.5.0_linux_amd64.deb > pet.deb && \
    dpkg -i pet.deb && \
	rm -f pet.deb && \
# Teller
    curl -L https://github.com/tellerops/teller/releases/download/v1.5.6/teller_1.5.6_Linux_x86_64.tar.gz | tar xvzf - -C /tmp && \
    mv /tmp/teller /usr/bin/teller && \
# chezmoi
    curl -L https://github.com/twpayne/chezmoi/releases/download/v2.27.0/chezmoi_2.27.0_linux_amd64.deb > chezmoi.deb && \
    dpkg -i chezmoi.deb && \
    rm -f chezmoi.deb && \
# Korb
    curl -L https://github.com/BeryJu/korb/releases/latest/download/korb_linux_amd64 > korb && \
    mv korb /usr/bin/korb && \
    chmod +x /usr/bin/korb && \
# kubectl
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y kubectl && \
# kubectx && kubens
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/kubectx > /usr/local/bin/kubectx && \
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/kubens > /usr/local/bin/kubens && \
    chmod +x /usr/local/bin/kubectx && \
    chmod +x /usr/local/bin/kubens && \
# Kubernetes stern
    curl -L https://github.com/stern/stern/releases/download/v1.19.0/stern_1.19.0_linux_amd64.tar.gz | tar xvzf - --strip-components=1 && \
    mv stern /usr/bin/stern && \
    chmod +x /usr/bin/stern && \
# krew
	curl -L https://github.com/kubernetes-sigs/krew/releases/download/v0.4.4/krew-linux_amd64.tar.gz | tar xvzf - -C /tmp && \
	mv /tmp/krew-linux_amd64 /usr/bin/krew && \
# viddy
	curl -L https://github.com/sachaos/viddy/releases/download/v0.3.6/viddy_0.3.6_Linux_x86_64.tar.gz | tar xvzf - -C /tmp && \
	mv /tmp/viddy /usr/bin && \
# k9s
	curl -L https://github.com/derailed/k9s/releases/download/v0.27.4/k9s_Linux_amd64.tar.gz | tar xvzf - -C /tmp && \
	mv /tmp/k9s /usr/bin && \
# helm 3
    curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash && \
# AWS CLI
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm awscliv2.zip && \
# infrahq
    echo 'deb [trusted=yes] https://apt.fury.io/infrahq/ /' | tee /etc/apt/sources.list.d/infrahq.list && \
    apt-get update && \
    apt-get install -y infra && \
# pulumi
	curl -L https://get.pulumi.com/releases/sdk/pulumi-v3.76.1-linux-x64.tar.gz | tar xvzf - -C /tmp --strip-components=1 && \
	mv /tmp/pulumi* /usr/bin && \
# terraform, vault, and packer
    curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - && \
    echo "deb [arch=amd64] https://apt.releases.hashicorp.com focal main" > /etc/apt/sources.list.d/hashicorp.list && \
    apt-get update && \
    apt-get install -y terraform vault packer && \
    setcap cap_ipc_lock= /usr/bin/vault && \
# SOPs
    curl -L https://github.com/getsops/sops/releases/download/v3.7.3/sops_3.7.3_amd64.deb > /tmp/sops_amd64.deb && \
    dpkg -i /tmp/sops_amd64.deb && \
# powershell
    curl -L https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb > packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install --no-install-recommends -y powershell && \
    rm -f packages-microsoft-prod.deb

RUN bash -c "rm -rf /tmp/*"

# Copy Commands for Various Tools
COPY --from=vmware/govc:v0.30.7 /govc /usr/bin/govc
COPY --from=istio/istioctl:1.18.2 /usr/local/bin/istioctl /usr/bin/istioctl
COPY --from=digitalocean/doctl:1.98.1 /app/doctl /usr/bin/doctl
COPY --from=fluxcd/flux-cli:v2.0.1 /usr/local/bin/flux /usr/bin/flux
COPY --from=klakegg/hugo:0.111.3-ext-ubuntu /usr/lib/hugo/hugo /usr/bin/hugo
COPY --from=gcr.io/kaniko-project/executor:v1.14.0 /kaniko/executor /usr/bin/kaniko
COPY --from=quay.io/coreos/etcd:v3.5.9 /usr/local/bin/etcdctl /usr/bin/etcdctl

COPY ./app/sshd_config /etc/ssh/sshd_config

# User chk
RUN useradd -m -s /bin/zsh -G sudo $DEV && \
	su -c "ssh-keygen -b 2048 -f /home/$DEV/.ssh/id_rsa -t rsa -q -N ''" $DEV && \
	passwd -d $DEV && \
	chmod 700 /home/$DEV/.ssh && \
	curl -L https://github.com/chkpwd.keys > /home/$DEV/.ssh/authorized_keys && \
	chown $DEV: /home/$DEV/.ssh/authorized_keys && \
	chmod 600 /home/$DEV/.ssh/authorized_keys && \
	chown root: /etc/ssh/sshd_config

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
    # Set Settings
    sh -c "$(curl -fsLS chezmoi.io/get)" -- init --apply chkpwd && \
    #chezmoi execute-template --init --promptString bw-pass=somepass < ~/.local/share/chezmoi/.chezmoi.toml.tmpl && \
    # Auto Complete for Tools
    helm completion zsh > $ZSH_CUSTOM/completions/helm.zsh && \
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/completion/_kubectx.zsh > $ZSH_CUSTOM/completions/_kubectx.zsh && \
    curl -L https://raw.githubusercontent.com/ahmetb/kubectx/master/completion/_kubens.zsh > $ZSH_CUSTOM/completions/_kubens.zsh && \
    flux completion zsh > $ZSH_CUSTOM/completions/flux.zsh && \
    hugo completion zsh > $ZSH_CUSTOM/completions/hugo.zsh && \
    echo 'autoload -U bashcompinit && \
          bashcompinit && \
          eval "$(register-python-argcomplete pipx)"' > $ZSH_CUSTOM/completions/pipx.zsh

CMD ["sudo", "/usr/sbin/sshd", "-D", "-e"]