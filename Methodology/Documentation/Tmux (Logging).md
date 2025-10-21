[Tmux logging](https://github.com/tmux-plugins/tmux-logging) is an excellent choice for terminal logging, and we should absolutely be using Tmux along with logging as this will save every single thing that we type into a Tmux pane to a log file

Usage
```bash
# Initial Setup
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
touch .tmux.conf            # conf file in home directory
tmux source ~/.tmux.conf    # execute in current session

# Adjust line limit of log file
set -g history-limit 50000

# Start new Tmux session
tmux new -s <name>
CTRL + B , then SHIFT + I  # installs plugin
CTRL + B, then SHIFT + P   # Begin Logging
# bottom of window should show loggins is enabled

# Stop Logging
CTRL + B, then SHIFT + P

# Retroactive logging (saves entire pane if you forgot dummy!!!)
CTRL + B, then ALT + SHIFT + P

# Screenshots
Hightlight, CTRL + B, then ALT+P

# Split panes
CTRL + B, then SHIFT + %   # Vertically
CTRL + B, then SHIFT + ""  # Horizontally (only 1 double quote!!) 

# Clear Pane history
Ctrl + B, then Alt + C
```

Some other plugins
	[tmux-sessionist](https://github.com/tmux-plugins/tmux-sessionist) - Gives us the ability to manipulate Tmux sessions from within a session.
	[tmux-pain-control](https://github.com/tmux-plugins/tmux-pain-control) - A plugin for controlling panes and providing more intuitive key bindings
	[tmux-resurrect](https://github.com/tmux-plugins/tmux-resurrect) - This extremely handy plugin allows us to restore our Tmux environment after our host restarts.