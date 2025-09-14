#!/bin/bash

# Log the stop attempt
echo "$(date): Attempting to stop scalping process..." >> /var/log/savedata.log

# Method 1: Find and kill by script name
pkill -f "main.py stream"

# Method 2: Alternative - kill by python process running the specific script
# ps aux | grep "main.py run" | grep -v grep | awk '{print $2}' | xargs kill -15

# Wait a moment for graceful shutdown
sleep 5

# Force kill if still running
pkill -9 -f "main.py stream"

# Log completion
echo "$(date): Stop script completed" >> /var/log/savedata.log

# Optional: Check if process is still running
if pgrep -f "main.py stream" > /dev/null; then
    echo "$(date): WARNING - Process still running!" >> /var/log/savedata.log
else
    echo "$(date): Process successfully stopped" >> /var/log/savedata.log
fi