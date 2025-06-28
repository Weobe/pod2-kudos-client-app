#!/bin/bash
set -e 

CLONE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ensure_path_in_shell_rc() {
  if [[ "$SHELL" == */zsh ]]; then
    SHELL_RC="$HOME/.zshrc"
  elif [[ "$SHELL" == */bash ]]; then
    SHELL_RC="$HOME/.bashrc"
  else
    SHELL_RC="$HOME/.profile"
  fi

  if ! grep -q 'export PATH="$HOME/bin:$PATH"' "$SHELL_RC"; then
    echo 'export PATH="$HOME/bin:$PATH"' >> "$SHELL_RC"
    echo "Added ~/bin to PATH in $SHELL_RC"
  else
    echo "~/bin already in PATH in $SHELL_RC"
  fi
}

install_commands() {
  mkdir -p "$HOME/bin"

  # Array of source → target pairs
  declare -a sources=("${@}")

  # Loop over each pair
  for ((i = 0; i < ${#sources[@]}; i+=2)); do
    local src="${sources[$i]}"
    local tgt="$HOME/bin/${sources[$i+1]}"

    if [ ! -f "$src" ]; then
      echo "❌ Source file '$src' does not exist."
      exit 1
    fi

    ln -sf "$CLONE_DIR/$src" "$tgt"

    chmod +x "$CLONE_DIR/$src"
    echo "✅ Installed '$tgt'"
  done
}

echo "Welcome to the Double Blind App setup script!"
echo "This script will help you set up the Double Blind App on your system."
echo "Compiling program....."
cargo build

echo "Setting up environment..."

install_commands \
                "send_pod_kudos.sh" "send-pod-kudos"

ensure_path_in_shell_rc
# Final message
echo "All steps completed. You can now start sending kudos!" 
