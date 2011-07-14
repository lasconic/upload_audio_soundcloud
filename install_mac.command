#!/bin/sh
PLUGIN_PATH=/Applications/MuseScore.app/Contents/Resources/plugins/soundcloud/
BASEDIR=`dirname $0`
sudo mkdir $PLUGIN_PATH
sudo cp $BASEDIR/soundcloud.js $PLUGIN_PATH
sudo cp $BASEDIR/*.ui $PLUGIN_PATH 
