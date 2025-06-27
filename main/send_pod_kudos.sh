#!/bin/bash

# Exit on error
set -e

sudo cargo run --release -- "$@"