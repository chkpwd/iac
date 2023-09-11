#!/bin/sh

# Login to Bitwarden and set the BW_SESSION environment variable
export BW_SESSION=$(/usr/bin/bw login $BW_EMAIL_ADDRESS $BW_PASSWORD --raw)

# Check if the login was successful
if [ -z "$BW_SESSION" ]; then
    echo "Failed to login to Bitwarden."
    exit 1
fi

# Set working directory
cd "$HOME" || return

# Init Chezmoi
sh -c "$(curl -fsLS chezmoi.io/get)" -- init --apply $GIT_USER

if [ -z "$PULL_REPOS" = "no" ]; then
    # Pull all git repos
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/chkpwd/scripts/main/Bash/git_pull_repos.sh)" -- $GIT_USER
fi

# Source zsh
source ~/.zshrc

# Pass commands to container
exec "$@"