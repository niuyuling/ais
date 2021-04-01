#!/bin/bash
#
# aixiao@aixiao.me
#


SHELL_FOLDER=$(cd "$(dirname "$0")"; pwd)       #脚本所在目录
SHELL_FOLDER=$(dirname $(readlink -f "$0"))

NAME="ais";         #tmux 会话名字

tmux new -d -s $NAME && tmux send -t $NAME 'cd ~' ENTER && tmux send -t $NAME "cd ${SHELL_FOLDER}/../; ./ais -l 127 -D 128" ENTER



