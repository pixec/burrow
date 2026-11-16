#!/bin/sh
# Stops the spike VM and its swtpm.
dir=${DIR:-/var/lib/burrow/spike-win}
tpmdir=${TPM_DIR:-$dir}
for p in /proc/[0-9]*; do
  case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in
    *cloud-hypervisor*"$dir/ch.sock"*|*swtpm*"$tpmdir/swtpm.sock"*) kill "${p#/proc/}" ;;
  esac
done
rm -f "$dir/ch.sock" "$tpmdir/swtpm.sock" "$dir/vsock.sock"
