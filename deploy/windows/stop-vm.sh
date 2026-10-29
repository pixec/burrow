#!/bin/sh
# Stops the spike VM and its swtpm.
dir=${DIR:-/var/lib/burrow/spike-win}
for p in /proc/[0-9]*; do
  case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in
    cloud-hypervisor*"$dir/ch.sock"*|swtpm*"$dir/swtpm.sock"*) kill "${p#/proc/}" ;;
  esac
done
rm -f "$dir/ch.sock" "$dir/swtpm.sock" "$dir/vsock.sock"
