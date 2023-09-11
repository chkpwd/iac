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

EOF
}

# Check for '-h' or '--help' arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

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
