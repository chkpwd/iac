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
sh -c "$(curl -fsLS chezmoi.io/get)" -- init --apply $CHEZMOI_GIT_USER

# Execute any commands passed to the docker run
exec "$@"