#!/bin/sh
# Stage the upstream module, utility and configuration for both Keyman images.
set -eu
revision=7380895665c3094a6f57640085bee97dcfeb1496
apt-get update
apt-get install -y --no-install-recommends autoconf automake ca-certificates curl g++ libssl-dev libsqlite3-dev libtool make pkg-config
mkdir /tmp/softhsm-build
cd /tmp/softhsm-build
curl --fail --location --retry 3 --output source.tar.gz "https://codeload.github.com/softhsm/SoftHSMv2/tar.gz/$revision"
echo '4a13de4512cbfcc29b6cc674f2f5f56972ab82c4081e8d25c486c96792718ee8  source.tar.gz' | sha256sum --check
tar xf source.tar.gz --strip-components=1
sh autogen.sh
./configure --prefix=/usr --sysconfdir=/etc/softhsm --localstatedir=/var --enable-mldsa --enable-slhdsa --enable-eddsa --with-objectstore-backend-db
make -j4
make install-strip DESTDIR=/opt/softhsm
rm /opt/softhsm/usr/lib/softhsm/libsofthsm2.a
