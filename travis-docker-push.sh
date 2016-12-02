#!/bin/bash

docker login --email=${DOCKER_HUB_EMAIL} --username=${DOCKER_HUB_USERNAME} --password=${DOCKER_HUB_PASSWORD}
make DOCKER_IMAGE_TAG=${TRAVIS_TAG:-latest} docker-push