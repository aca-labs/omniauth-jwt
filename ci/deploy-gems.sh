#!/usr/bin/env bash

set -e

echo "Building Gem"
rm -f pkg/*.gem

bundle install
bundle exec rake build

gem inabox --host $GEM_SERVER pkg/*.gem
