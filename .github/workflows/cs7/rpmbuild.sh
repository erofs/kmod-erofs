#!/bin/sh

# Generate a release tarball
tarball_file=$(spectool -s 0 $1 | cut -d' ' -f2)
tarball_dir=$(echo "$tarball_file" | sed -e 's/\.tar.*$//')

git archive --format=tar.gz --prefix=${tarball_dir}/ -o /tmp/${tarball_file} HEAD
mv /tmp/${tarball_file} /home/rpmbuild/rpmbuild/SOURCES

yum-builddep -y $1
sudo -u rpmbuild rpmbuild -ba $1
