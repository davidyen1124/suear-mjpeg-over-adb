#!/bin/zsh
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
viewer_dir="${0:A:h}"
exec python3 "$viewer_dir/suear_viewer.py" --open
