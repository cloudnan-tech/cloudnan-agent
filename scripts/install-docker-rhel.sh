#!/bin/bash
# Docker installation script for RHEL/CentOS/Fedora
# Used by Cloudnan App Store

set -e

echo "Installing Docker on RHEL/CentOS/Fedora..."

# Remove old versions
yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine 2>/dev/null || true

# Install dependencies
yum install -y yum-utils

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="centos"
fi

# Add Docker repository
case $DISTRO in
    fedora)
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        ;;
    *)
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        ;;
esac

# Install Docker
if command -v dnf &> /dev/null; then
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
    yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Verify installation
docker --version

echo "Docker installed successfully!"
