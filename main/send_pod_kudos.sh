#!/bin/bash

# Exit on error
set -e

cargo run --release -- "$@"