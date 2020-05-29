#!/bin/bash
#
# Start AIS
# date: 20200526
#

SHELL_FOLDER=$(cd "$(dirname "$0")"; pwd)       #脚本所在目录
SHELL_FOLDER=$(dirname $(readlink -f "$0"))

${SHELL_FOLDER}/ais -l 1080 -D 128 -d &>> ${SHELL_FOLDER}/info.txt

