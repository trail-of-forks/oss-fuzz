# Copyright 2023 Google LLC
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
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool

# Install CUDA
RUN mkdir $SRC/cuda-install && \
    cd $SRC/cuda-install && \
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin && \
    mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600 && \
    wget https://developer.download.nvidia.com/compute/cuda/12.9.1/local_installers/cuda-repo-ubuntu2004-12-9-local_12.9.1-575.57.08-1_amd64.deb && \
    dpkg -i cuda-repo-ubuntu2004-12-9-local_12.9.1-575.57.08-1_amd64.deb && \
    cp /var/cuda-repo-ubuntu2004-12-9-local/cuda-AE7C1B4C-keyring.gpg /usr/share/keyrings/ && \
    apt-get update -y && apt-get install cuda-toolkit-12-9 -y && \
    rm -rf $SRC/cuda-install

RUN git clone --depth 1 https://github.com/NVIDIA/nccl nccl
WORKDIR nccl
COPY build.sh *.cpp $SRC/
