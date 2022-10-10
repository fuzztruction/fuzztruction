#!/usr/bin/env bash

set -eu

text_red=$(tput setaf 1)    # Red
text_green=$(tput setaf 2)  # Green
text_bold=$(tput bold)      # Bold
text_reset=$(tput sgr0)     # Reset your text

function log_error {
    echo "${text_bold}${text_red}${1}${text_reset}"
}

function log_success {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

function rebuild {
    if [[ ! -z "${!PREBUILT_ENV_VAR_NAME:-}" ]]; then
        log_error "[!] Environment checks failed, even though this is a prebuilt image."
        exit 1
    fi

    log_success "[+] Building missing files: cd /home/user/fuzztruction/ && cargo build --workspace --all-targets"
    cd /home/user/fuzztruction
    if ! cargo build --workspace --all-targets; then
        log_error "[!] Hmm... build failed... Wrong rustc version?"
        exit 1
    fi
    log_success "[+] Build was successfull!"
    log_success "[+] Please execute $0 again to refresh the ld cache"
    exit 0
}

log_success "[+] Checking whether libgenerator_agent.so can be found by the linker."
sudo ldconfig
if ! ldconfig -N -v 2>/dev/null | grep -q "libgenerator_agent.so"; then
    log_error "[!] Failed to find libgenerator_agent.so!"
    rebuild
fi
if ! find ~/fuzztruction/generator -name fuzztruction-source-llvm-pass.so | grep -q .; then
    log_error "[!] Failed to find fuzztruction-source-llvm-pass.so !"
    rebuild
fi

log_success "[+] Your environment looks superb .. just like you do!"
