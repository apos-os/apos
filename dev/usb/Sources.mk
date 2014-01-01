# Copyright 2014 Andrew Oates.  All Rights Reserved.
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

$(eval $(BEGIN_SOURCES))

LOCAL_SOURCES := \
  bus.c \
  device.c \
  usb.c \
  usb_driver.c \
  request.c \
  descriptor.c \

LOCAL_SUBDIRS := uhci drivers

$(foreach subdir,$(LOCAL_SUBDIRS),$(eval $(call SOURCES_SUBDIR,$(subdir))))

$(eval $(END_SOURCES))
