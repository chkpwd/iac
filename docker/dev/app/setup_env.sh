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
  BWS_ACCESS_TOKEN    Your Bitwarden access token. Link: https://bitwarden.com/help/access-tokens/
  BW_API_KEY          Your Bitwarden API key, if you have one.
  BW_EMAIL_ADDRESS    Your Bitwarden email address, used for login.
  BW_PASSWORD         Your Bitwarden password.
  GIT_USER            Your Git username, for Chezmoi initialization.
  PULL_REPOS          If set to "yes", pulls all git repos. If set to "no", skips this step.

EOF
}

# Chezmoi conf file
CHEZMOI_CONF_DIR=~/.config/chezmoi
CHEZMOI_CONF="${CHEZMOI_CONF_DIR}/chezmoi.yaml"

# Check for '-h' or '--help' arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Function to set up Chezmoi configuration
setup_chezmoi_conf() {
  # Ensure the Chezmoi configuration directory exists
  mkdir -p "$CHEZMOI_CONF_DIR"
  
  # Prompt user for access token
  read -rp "Enter your access token: " access_token
  
  # Create Chezmoi configuration file with access token
  echo "data:
  accessToken: $access_token" > "$CHEZMOI_CONF"
}

# Login to Bitwarden and set the BW_SESSION environment variable
if [[ -z "$BWS_ACCESS_TOKEN" ]] && [[ -z $(yq '(.[] | select(has("accessToken")).accessToken)' "$CHEZMOI_CONF") ]]; then
  # https://bitwarden.com/help/personal-api-key/
  if [[ -n "$BW_API_KEY" ]]; then
    export BW_SESSION=$(/usr/bin/bw login --apikey $BW_CLIENTID $BW_CLIENTSECRET --raw)
  else
    setup_chezmoi_conf
    access_token=$(yq -r '.data.accessToken' "$CHEZMOI_CONF")
    export BW_SESSION=$(/usr/bin/bw login --apikey $access_token --raw)
  fi
fi

# Set working directory
cd "$HOME" || return

# Init Chezmoi
chezmoi init --apply $GIT_USER

if [ "$PULL_REPOS" = "no" ]; then
    echo "Skipping pulling git repos."
elif [ "$PULL_REPOS" = "yes" ]; then
    # Pull all git repos
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/chkpwd/scripts/main/Bash/git_pull_repos.sh)" -- $GIT_USER
else
    echo "PULL_REPOS not set to 'yes' or 'no'."
fi

# Source zsh
zsh -c 'source ~/.zshrc'
