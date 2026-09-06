# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

# Use Dockerfile to get dependabot version bumps after new image is released
FROM ghcr.io/eclipse-score/devcontainer:v1.11.0

# Build argument for dynamic username (defaults to 'vscode' if not provided)
ARG USERNAME=vscode

# Phase 1: Rename 'vscode' to satisfy the QNX license criteria
RUN if [ "${USERNAME}" != "vscode" ]; then \
        usermod -l ${USERNAME} vscode \
        && groupmod -n ${USERNAME} vscode \
        && usermod -d /home/${USERNAME} -m ${USERNAME} \
        && ln -s /home/${USERNAME} /home/vscode  \
        && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
        && chmod 0440 /etc/sudoers.d/${USERNAME}; \
    fi

# Phase 2: Dynamically source the host's captured KVM group configuration file.
# If KVM is present on the host, it builds the group and assigns the user. If not, it skips.
RUN --mount=type=bind,source=.env,target=/tmp/.env \
    set -a && . /tmp/.env && set +a; \
    if [ -n "${HOST_KVM_GID}" ] && [ "${HOST_KVM_GID}" != "NONE" ]; then \
        echo "Configuring environment layer for Host KVM GID: ${HOST_KVM_GID}"; \
        if ! getent group kvm >/dev/null 2>&1; then \
            groupadd -g "${HOST_KVM_GID}" -o kvm; \
        fi; \
        usermod -aG kvm "${USERNAME}"; \
        echo "Successfully assigned ${USERNAME} to KVM group."; \
    else \
        echo "KVM device not detected on the host system. Skipping KVM group creation."; \
    fi

# Phase 3: Install virtualization tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set the default user for the container
USER ${USERNAME}
