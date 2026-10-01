#!/bin/sh
# Called only inside samba_dns.py's networkless, host-readonly build sandbox.
set -eu
source_dir=$1
cd "$source_dir"
export SOURCE_DATE_EPOCH=1784734138 PYTHONHASHSEED=1
export CFLAGS="-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -fexceptions -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security -fstack-clash-protection -fcf-protection -fstack-protector-strong -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -ffile-prefix-map=$source_dir=/usr/src/telos-samba-4.24.5"
export LDFLAGS='-Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,pack-relative-relocs -Wl,-rpath,/usr/lib/samba:/usr/lib'
./configure --prefix=/usr --libdir=/usr/lib --enable-fhs --disable-rpath \
    --without-ad-dc --disable-python --without-ldap --without-ads \
    --without-winbind --disable-cups --disable-iprint --without-pam \
    --without-utmp --disable-avahi --without-regedit --without-winexe \
    --disable-glusterfs --disable-cephfs --disable-spotlight --disable-wsp \
    --without-cluster-support --without-json --with-system-mitkrb5 \
    --enable-selftest
./buildtools/bin/waf build --targets=ndr_nbt,test_ndr_dns_nbt -j4
