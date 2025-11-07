## Tmux
[Tmux logging](https://github.com/tmux-plugins/tmux-logging) is an excellent choice for terminal logging, and we should absolutely be using Tmux along with logging as this will save every single thing that we type into a Tmux pane to a log file

Initial Setup
```bash
# Initial Setup
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
touch .tmux.conf            # conf file in home directory
vim .tmux.conf
	# List of plugins
	
	set -g @plugin 'tmux-plugins/tpm'
	set -g @plugin 'tmux-plugins/tmux-sensible'
	set -g @plugin 'tmux-plugins/tmux-logging'
	
	# Initialize TMUX plugin manager (keep at bottom)
	run '~/.tmux/plugins/tpm/tpm'
	
	# Adjust line limit of log file
	set -g history-limit 50000
	
	# Enable mouse scrolling
	set -g mouse on
	
	# Adust log location
	set -g @logging-path "~/.tmux/logs"
	
	# Enable copy-paste
	bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "xclip"

tmux source ~/.tmux.conf    # execute in current session

# Edit .zshrc to have all panes log (i like zsh...)
echo 'tmux pipe-pane "cat >> ~/.tmux/logs/tmux_session_#S_#I_#P_$(date +%Y%m%d%H%M%S).log" 2> /dev/null' >> ~/.zshrc

# Start new Tmux session
tmux new -s setup
PREFIX, then SHIFT + I  # installs plugin
```

Usage
```bash
# PREFIX
Ctrl + B

# Start new Tmux session
tmux new -s <name>

# Start Logging / Stop Logging
PREFIX, then SHIFT + P
# Now all terminal commands get saved to:
~/.tmux/logs/tmux-<name>-0-0-<date>.log

# End Session
exit

# Retroactive logging (saves entire pane if you forgot dummy!!!)
PREFIX, then ALT + SHIFT + P

# Screenshots
Hightlight, PREFIX, then ALT+P

# Split panes
## NOTE -- You must enable logging for EACH pane
PREFIX, then SHIFT + %   # Vertically
PREFIX, then SHIFT + ""  # Horizontally (only 1 double quote!!) 

# Move between planes
PREFIX, o # if mouse is enabled, not an issue...

# Copy text
SHIFT + Highlight, copy #ideally you only have horizontal planes because of this...

# Clear Pane history
PREFIX, then Alt + C

# CLOSE Pane
Prefix, then X
```
[Cheatsheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/)

Some other plugins
	[tmux-sessionist](https://github.com/tmux-plugins/tmux-sessionist) - Gives us the ability to manipulate Tmux sessions from within a session.
	[tmux-pain-control](https://github.com/tmux-plugins/tmux-pain-control) - A plugin for controlling panes and providing more intuitive key bindings
	[tmux-resurrect](https://github.com/tmux-plugins/tmux-resurrect) - This extremely handy plugin allows us to restore our Tmux environment after our host restarts.

## Terminator

Instalation
```bash
sudo apt install terminator
```

Setup Logging
```bash
# Enable Logger plugin
terminator > right-click > preferences > plugins > Logging -- Enable

# Start logging
Right-CLick > Start Logger > Save log file

# Stop Logging
Right-click > Stop Logger
```

Usage
```bash
# Start
terminator

# Shortcuts -- or just right click
Ctrl-Shift-o  # Horizontal split
Ctrl-Shift-e  # Vertical split
Ctrl-Shift-t  # New tab
Ctrl-shift-i  # New window
Ctrl-Shift-w  # Close Terminal/tab
Ctrl-Shift-q  # Close window, all tabs
```