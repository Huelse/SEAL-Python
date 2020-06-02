#!/bin/bash

# @Author: GeorgeRaven <archer>
# @Date:   2020-05-29T13:56:26+01:00
# @Last modified by:   archer
# @Last modified time: 2020-05-29T13:58:56+01:00
# @License: please see LICENSE file in project root

set -e
docker build -t huelse/seal-python ./../. -f ./../Dockerfile
docker run -it huelse/seal-python python3 /app/tests/unittests.py
