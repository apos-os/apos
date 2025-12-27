#!/bin/bash
# Copyright 2025 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

SIZE_KB=128
FILENAME=generated.img
EXT2_BLKSZ=1024
MOUNT=/tmp/gen_img

echo Creating blank image file
dd if=/dev/zero of=${FILENAME} bs=1024 count=${SIZE_KB}

echo Overriding system time
sudo timedatectl set-ntp false
sudo date -s "2025-01-01 12:00:00"

echo Creating ext2 filesystem
# Uses some random UUIDs I generated online
mkfs.ext2 -O none -b ${EXT2_BLKSZ} \
	-E hash_seed=454df397-973a-488e-b720-57cd6f75beb9 \
	-U c93b9ee8-2523-49aa-856c-6aabbb6671c9 \
	${FILENAME}

echo Adding files
mkdir -p ${MOUNT}
sudo mount ${FILENAME} ${MOUNT}
clean_up () {
  sudo umount ${MOUNT}
}
trap clean_up EXIT

echo -n abcd | sudo tee ${MOUNT}/file1 > /dev/null
sudo mkdir ${MOUNT}/dir
echo -n 1234 | sudo tee ${MOUNT}/dir/file2 > /dev/null
sudo umount ${MOUNT}
trap - EXIT

echo Restoring system time
sudo timedatectl set-ntp true
