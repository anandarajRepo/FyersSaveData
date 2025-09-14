#!/bin/bash
truncate -s 0 /var/log/savedata.log
cd /root/FyersSaveData
source venv/bin/activate
python main.py stream >> /var/log/savedata.log 2>&1