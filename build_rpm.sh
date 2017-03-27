#!/bin/bash

echo "Adjusting build number..."

OIFS=$IFS
IFS='

'

release=""

taglist=`git tag -l`
tags=($taglist)

for ((i=${#tags[@]}-1; i >=0; i--)); do
    if [[ "${tags[i]}" != *"alpha"* ]]; then
        release=${tags[i]}
        break
    fi
done

if [ -z "$release"  ]; then
    echo "Could not find latest release tag!"
else
    echo "Most recent release tag: $release"
fi

IFS=$OIFS

release=`echo "$release" | awk -F. '{$NF+=1; OFS="."; print $0}'`
new_release=$release
new_release+="-${BUILD_NUMBER}alpha"
release=`echo "$release" | awk -F'v' '{print $2}'`
echo "Issuing release $new_release..."
echo "New base version: $release..."

echo "Building the scytale rpm..."

pushd ..
cp -r scytale scytale-$release
tar -czvf scytale-$new_release.tar.gz scytale-$release
mv scytale-$new_release.tar.gz /root/rpmbuild/SOURCES
rm -rf scytale-$release
popd

rpmbuild -ba --define "_ver $release" --define "_releaseno ${BUILD_NUMBER}alpha" --define "_fullver $new_release" scytale.spec

pushd ..
echo "$new_release" > versionno.txt
popd

