#!/bin/bash
set -ex


tag=$TRAVIS_TAG
base_image_name=mietzekotze/culper-server
tagged_image_name=${base_image_name}:${tag}

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

docker build --build-arg CULPER_VER=${tag} -t ${tagged_image_name} .

if ![[ $(echo $tag | grep -E "(alpha|beta|rc)") ]]
then
    docker tag ${tagged_image_name} ${base_image_name}:latest
fi

docker push ${base_image_name}
