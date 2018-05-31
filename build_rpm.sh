#!/bin/bash

NAME=scytale
ARCH=x86_64
DIST=el6

echo "Adjusting build number..."

taglist=`git tag -l`
tags=($taglist)

release=${tags[${#tags[@]}-1]}

if [ -z "$release"  ]; then
    echo "Could not find latest release tag!"
else
    echo "Most recent release tag: $release"
fi

release=`echo "$release" | sed -e 's/^.*\([0-9]\+\.[0-9]\+\.[0-9]\+\).*\+$/\1/'`
new_release="$release-${BUILD_NUMBER}"

echo "Issuing release $new_release..."
echo "New base version: $release..."

echo "Building the ${NAME} rpm..."

pushd ..
cp -r ${NAME} ${NAME}-$release
tar -czvf ${NAME}-$new_release.tar.gz ${NAME}-$release
mv ${NAME}-$new_release.tar.gz /root/rpmbuild/SOURCES
rm -rf ${NAME}-$release
popd

# Merge the changelog into the spec file so we're consistent
cat ChangeLog >> ${NAME}.spec

yes "" | rpmbuild -ba --sign \
    --define "_signature gpg" \
    --define "_gpg_name Comcast Xmidt Team <CHQSV-Xmidt-Gpg@comcast.com>" \
    --define "_ver $release" \
    --define "_releaseno ${BUILD_NUMBER}" \
    --define "_fullver $new_release" \
    ${NAME}.spec

if [ ! -f /root/rpmbuild/RPMS/${ARCH}/${NAME}-${BUILD_NUMBER}.${DIST}.${ARCH}.rpm ]; then
    echo "RPM not present.  Check steps prior for root cause."
    exit 1
fi

pushd ..
echo "$new_release" > versionno.txt
popd

