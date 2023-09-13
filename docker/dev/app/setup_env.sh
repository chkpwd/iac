#!/usr/bin/env bash

show_help() {
  cat << EOF
Usage: ./$0 [OPTION]

This script is designed to be sourced to export variables into your shell.
To source this script:

    source $0

or

    . $0

Options:
  -h      Display this help and exit

Environment Variables:
  BW_API_KEY          Your Bitwarden API key, if you have one.
  BW_EMAIL_ADDRESS    Your Bitwarden email address, used for login.
  BW_PASSWORD         Your Bitwarden password.
  GIT_USER            Your Git username, for Chezmoi initialization.
  PULL_REPOS          If set to "yes", pulls all git repos. If set to "no", skips this step.

EOF
}

# Chezmoi conf file
CHEZMOI_CONF=~/.config/chezmoi/chezmoi.yaml

# Check for '-h' or '--help' arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Login to Bitwarden and set the BW_SESSION environment variable
if [[ -z "$BWS_ACCESS_SESSION" || yq -r '.data.accessToken' $CHEZMOI_CONF ]]; then
   # https://bitwarden.com/help/personal-api-key/
   if [[ "$BW_API_KEY" ]]; then
      export BW_SESSION=$(/usr/bin/bw login --apikey $BW_API --raw)
   else
      export BW_SESSION=$(/usr/bin/bw login $BW_EMAIL_ADDRESS $BW_PASSWORD --raw)
   fi
fi

# Set working directory
cd "$HOME" || return

# Init Chezmoi
sh -c "$(curl -fsLS chezmoi.io/get)" -- init --apply $GIT_USER

if [ "$PULL_REPOS" = "no" ]; then
    echo "Skipping pulling git repos."
elif [ "$PULL_REPOS" = "yes" ]; then
    # Pull all git repos
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/chkpwd/scripts/main/Bash/git_pull_repos.sh)" -- $GIT_USER
else
    echo "PULL_REPOS not set to 'yes' or 'no'. Ignoring."
fi

# Source zsh
source ~/.zshrc
