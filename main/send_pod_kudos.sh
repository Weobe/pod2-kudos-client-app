#!/bin/bash

# Exit on error
set -e
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do                       # $SOURCE is a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"                 # follow the link one step
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"   # handle relative links
done
SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

cd "$SCRIPT_DIR"
cargo run --release -- "$@"