#!/bin/sh

# Login to Bitwarden and set the BW_SESSION environment variable
export BW_SESSION=$(/usr/bin/bw login $BW_EMAIL_ADDRESS $BW_PASSWORD --raw)

# Check if the login was successful
if [ -z "$BW_SESSION" ]; then
    echo "Failed to login to Bitwarden."
    exit 1
fi

# Execute any commands passed to the docker run
exec "$@"