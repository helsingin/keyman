#!/bin/sh
set -eu

if [ "${KEYMAN_TPM2_DEMO:-1}" = "1" ]; then
  state_dir="${KEYMAN_TPM2_STATE_DIR:-/var/lib/keyman/swtpm}"
  mkdir -p "$state_dir"
  swtpm socket \
    --tpm2 \
    --tpmstate "dir=$state_dir" \
    --ctrl type=tcp,bindaddr=127.0.0.1,port=2322 \
    --server type=tcp,bindaddr=127.0.0.1,port=2321 \
    --flags not-need-init,startup-clear &
  export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}"
  i=0
  while [ "$i" -lt 50 ]; do
    if tpm2_getrandom -o /tmp/keyman-tpm2-startup.bin 4 >/dev/null 2>&1; then
      rm -f /tmp/keyman-tpm2-startup.bin
      break
    fi
    i=$((i + 1))
    sleep 0.1
  done
fi

exec /app/keymand
