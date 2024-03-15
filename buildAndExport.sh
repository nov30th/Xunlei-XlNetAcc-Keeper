#!/bin/zsh
set -e

# Build the project with docker with name nov30th/xunlei_ros:v1
docker build -t nov30th/xunlei_ros:v1 .

mkdir -p dist

# export the docker image to dist/xunlei_ros_v1.tar
docker save nov30th/xunlei_ros:v1 -o dist/xunlei_ros_v1.tar

