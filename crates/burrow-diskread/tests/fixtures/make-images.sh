#!/bin/sh
# Makes the ext4 images the reader's tests read, the way a template's root
# disk is made (mkfs.ext4 -d, 4 KiB blocks), which keeps times to the second. Run as root in a Debian
# container, with --privileged for the image whose journal is left to replay:
#
#   docker run --rm --privileged -v "$PWD:/out" debian:bookworm-slim sh /out/make-images.sh
set -eu
apt-get update -qq && apt-get install -y -qq e2fsprogs attr acl libcap2-bin >/dev/null
tree=$(mktemp -d)
cd "$tree"
mkdir -p home/me/.ssh var/lib/app/many var/lib/big etc
echo "hello" > home/me/notes.txt
chown -R 1000:1001 home/me
chmod 0700 home/me/.ssh
echo "key" > home/me/.ssh/id
chown 1000:1001 home/me/.ssh/id
chmod 0600 home/me/.ssh/id
touch -d '2001-02-03 04:05:06' home/me/notes.txt
ln -s notes.txt home/me/fast
ln -s "$(printf 'long/%.0s' $(seq 1 30))target" home/me/slow
printf 'data' > var/lib/app/db
ln var/lib/app/db var/lib/app/db.link
truncate -s 3G var/lib/big/sparse
printf 'end' >> var/lib/big/sparse
cp /bin/true var/lib/app/ping
setcap cap_net_raw+ep var/lib/app/ping
chmod 4755 var/lib/app/ping
setfattr -n user.small -v tiny var/lib/app/db
setfattr -n user.big -v "$(head -c 2000 /dev/zero | tr '\0' x)" var/lib/app/db
setfacl -m u:1000:rw var/lib/app/db
i=0; while [ $i -lt 3000 ]; do : > var/lib/app/many/file-$i; i=$((i+1)); done
mknod var/lib/app/null c 1 3
mkfifo var/lib/app/pipe
chmod 0750 var/lib/app
touch -d '2010-01-01 00:00:00' var/lib/app
mkfs.ext4 -q -F -L burrow-root -b 4096 -d "$tree" /tmp/root.ext4 64M
gzip -9 -c /tmp/root.ext4 > /out/root.ext4.gz

# The same tree, then written to while mounted and copied once the change
# is committed to the journal but before writeback puts it in place: it is
# in the journal only, which debugfs (which ignores the journal) confirms.
cp /tmp/root.ext4 /tmp/dirty.ext4
mkdir -p /mnt/dirty
mount -o loop,commit=1,nodelalloc /tmp/dirty.ext4 /mnt/dirty
echo "journaled" > /mnt/dirty/home/me/late.txt
touch -d '2020-02-02 02:02:02.987654321' /mnt/dirty/home/me/late.txt
rm /mnt/dirty/home/me/notes.txt
sleep 3
cp /tmp/dirty.ext4 /tmp/dirty-copy.ext4
umount /mnt/dirty
gzip -9 -c /tmp/dirty-copy.ext4 > /out/dirty.ext4.gz
debugfs -R 'ls /home/me' /tmp/dirty-copy.ext4 2>/dev/null | grep -q late.txt && {
    echo "the change reached its place before the copy; run again" >&2
    exit 1
}
dumpe2fs -h /tmp/dirty-copy.ext4 2>/dev/null | grep -q needs_recovery
