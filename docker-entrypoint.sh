#!/bin/bash

set -e

echo " # Running init"
certifire-manager init -p changeme
echo " # Done"

exec "$@"