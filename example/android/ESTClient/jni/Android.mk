# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS	:= -g -I/home/foleyj/Iron/Vodaphone/usr/include 
#LOCAL_LDFLAGS	:= -L/nobackup/tmp/Wood/est/android/ssl/lib -L/nobackup/tmp/Wood/est/android/est/lib
LOCAL_LDLIBS	:= -L/home/foleyj/Iron/Vodaphone/usr/est/lib -L/home/foleyj/Iron/Vodaphone/usr/lib -L. -llog -lest -lsafe -lssl -lcrypto  
LOCAL_MODULE    := estwrap
LOCAL_SRC_FILES := est_wrapper.c

include $(BUILD_SHARED_LIBRARY)

