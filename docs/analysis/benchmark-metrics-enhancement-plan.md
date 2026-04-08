#!/bin/bash

# --- 1. Fix Python 3.14 Headers (System Level) ---
echo "Verifying Python 3.14 development headers..."
if [ ! -f "/usr/include/python3.14/Python.h" ]; then
    echo "Headers missing. Attempting to install..."
    sudo apt update && sudo apt install -y python3.14-dev build-essential
fi

# --- 2. Install Safe LiteLLM (Post-Compromise) ---
# Version 1.83.0+ contains the fixes for the March 2026 TeamPCP attack.
echo "Updating LiteLLM to secure version..."
pip install --upgrade "litellm[proxy]>=1.83.0" uvloop orjson

# --- 3. Update Model Configuration ---
cat <<EOF > litellm_config.yaml
model_list:
  - model_name: "claude-opus-4-6"
    litellm_params:
      model: "anthropic/claude-opus-4-6"
  - model_name: "claude-3-5-sonnet-latest"
    litellm_params:
      model: "ollama_chat/gemma4:26b-moe-q4_k_m"
      api_base: "http://localhost:11434"
      drop_params: true
      remove_headers: ["anthropic-beta", "x-claude-code-attribution"]
EOF

# --- 4. Start Proxy ---
fuser -k 4000/tcp > /dev/null 2>&1
nohup litellm --config litellm_config.yaml --port 4000 > litellm.log 2>&1 &
sleep 3

# --- 5. Export Variables for Claude Code ---
export ANTHROPIC_BASE_URL="http://localhost:4000"

# This maps the "opusplan" command to your specific models
export ANTHROPIC_DEFAULT_OPUS_MODEL="claude-opus-4-6"
export ANTHROPIC_DEFAULT_SONNET_MODEL="claude-3-5-sonnet-latest"

# Launch!
echo "Launching Claude Code with Opus 4.6 & Gemma 4..."
claude --model opusplan
