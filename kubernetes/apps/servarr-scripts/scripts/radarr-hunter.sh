#!/usr/bin/env bash

# Configuration
API_KEY=${API_KEY:-"your-api-key"}
API_URL=${API_URL:-"http://your-radarr-address:7878"}

# How many movies to process before restarting the search cycle
MAX_MOVIES=${MAX_MOVIES:-1}

# Sleep duration in seconds after fully processing a movie (300=5min)
SLEEP_DURATION=${SLEEP_DURATION:-300}

# Shorter sleep duration between each processed movie (30=0.5min)
REFRESH_DURATION=${REFRESH_DURATION:-30}

# Set to true to pick movies randomly, false to go in order
RANDOM_SELECTION=${RANDOM_SELECTION:-true}

echo "Retrieving missing movies from Radarr..."

# Fetch all monitored movies that do not have files
MISSING_MOVIES_JSON=$(curl -s \
  -H "X-Api-Key: $API_KEY" \
  "$API_URL/api/v3/movie" | \
  jq '[.[] | select(.monitored == true and .hasFile == false)]'
)

if [ -z "$MISSING_MOVIES_JSON" ]; then
  echo "ERROR: Unable to retrieve movie data from Radarr. Exiting..."
  exit 1
fi

TOTAL_MISSING=$(echo "$MISSING_MOVIES_JSON" | jq 'length')
if [ "$TOTAL_MISSING" -eq 0 ]; then
  echo "No missing movies found. Exiting..."
  exit 0
fi

echo "Found $TOTAL_MISSING missing movie(s)."
echo "Using ${RANDOM_SELECTION:+random}${RANDOM_SELECTION:-sequential} selection."
echo "Will process up to $MAX_MOVIES movies with a longer sleep of $SLEEP_DURATION seconds after the final one."

MOVIES_PROCESSED=0
ALREADY_CHECKED=()

for ((i=0; i<TOTAL_MISSING && MOVIES_PROCESSED < MAX_MOVIES; i++)); do
  # Check if we've already processed this movie
  if [[ " ${ALREADY_CHECKED[*]} " =~ " ${i} " ]]; then
    continue
  fi

  # Select the next movie index based on the selection method
  if [ "$RANDOM_SELECTION" = true ] && [ "$TOTAL_MISSING" -gt 1 ]; then
    while true; do
      INDEX=$((RANDOM % TOTAL_MISSING))
      if [[ ! " ${ALREADY_CHECKED[*]} " =~ " ${INDEX} " ]]; then
        break
      fi
    done
  else
    INDEX=$i
  fi

  ALREADY_CHECKED+=("$INDEX")

  # Extract movie information
  MOVIE=$(echo "$MISSING_MOVIES_JSON" | jq ".[$INDEX]")
  MOVIE_ID=$(echo "$MOVIE" | jq '.id')
  MOVIE_TITLE=$(echo "$MOVIE" | jq -r '.title')
  MOVIE_YEAR=$(echo "$MOVIE" | jq -r '.year')

  echo "Selected missing movie \"$MOVIE_TITLE ($MOVIE_YEAR)\"..."

  # 1. Refresh the movie
  echo "1. Refreshing movie information for \"$MOVIE_TITLE\"..."
  REFRESH_COMMAND=$(curl -s -X POST \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"RefreshMovie\",\"movieIds\":[$MOVIE_ID]}" \
    "$API_URL/api/v3/command"
  )

  REFRESH_ID=$(echo "$REFRESH_COMMAND" | jq '.id // empty')
  if [ -z "$REFRESH_ID" ]; then
    echo "WARNING: Could not refresh \"$MOVIE_TITLE\". Response was:"
    echo "$REFRESH_COMMAND"
    echo "Skipping this movie. Sleeping 10 seconds..."
    sleep 10
    continue
  fi

  echo "Refresh command accepted (ID: $REFRESH_ID). Waiting 5 seconds for refresh to complete..."
  sleep 5

  # 2. Search for the movie using "MoviesSearch"
  echo "2. Searching for \"$MOVIE_TITLE\"..."
  SEARCH_COMMAND=$(curl -s -X POST \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"MoviesSearch\",\"movieIds\":[$MOVIE_ID]}" \
    "$API_URL/api/v3/command"
  )

  SEARCH_ID=$(echo "$SEARCH_COMMAND" | jq '.id // empty')
  if [ -n "$SEARCH_ID" ]; then
    echo "Search command accepted (ID: $SEARCH_ID)."
  else
    echo "WARNING: Search command failed for \"$MOVIE_TITLE\". Response was:"
    echo "$SEARCH_COMMAND"
  fi

  echo "Waiting 5 seconds for search operation..."
  sleep 5

  # 3. Rescan the movie folder
  echo "3. Rescanning movie folder for \"$MOVIE_TITLE\"..."
  RESCAN_COMMAND=$(curl -s -X POST \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"RescanMovie\",\"movieIds\":[$MOVIE_ID]}" \
    "$API_URL/api/v3/command"
  )

  RESCAN_ID=$(echo "$RESCAN_COMMAND" | jq '.id // empty')
  if [ -n "$RESCAN_ID" ]; then
    echo "Rescan command accepted (ID: $RESCAN_ID)."
  else
    echo "WARNING: Rescan command not available or failed."
  fi

  MOVIES_PROCESSED=$((MOVIES_PROCESSED + 1))

  # Sleep before processing the next movie
  if [ "$MOVIES_PROCESSED" -ge "$MAX_MOVIES" ]; then
    echo "Processed $MOVIES_PROCESSED movies. Sleeping for $SLEEP_DURATION seconds..."
    sleep "$SLEEP_DURATION"
  else
    echo "Movie refreshed. Sleeping for $REFRESH_DURATION seconds before continuing..."
    sleep "$REFRESH_DURATION"
  fi
done

echo "Done. Processed $MOVIES_PROCESSED missing movies."
