#!/bin/zsh
set -e

# Build the project with docker with name nov30th/xunlei_ros:v1
docker build -t nov30th/xunlei_ros:v1 .

mkdir -p dist

skopeo copy -f v2s2 docker-daemon:nov30th/xunlei_ros:v1 docker-archive:dist/image.tar
