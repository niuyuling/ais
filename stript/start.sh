#!/bin/bash
#
# aixiao@aixiao.me
#


SHELL_FOLDER=$(cd "$(dirname "$0")"; pwd)       #脚本所在目录
SHELL_FOLDER=$(dirname $(readlink -f "$0"))

${SHELL_FOLDER}/../ais -l 127 -D 128 -d

