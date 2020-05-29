#!/bin/bash

docker build -t huelse/seal-python . -f Dockerfile
docker run -it huelse/seal-python bash
