"""The elevated helper: the only part of the product that runs with administrator rights.

It records activity into the live database and accepts a fixed list of commands over a named
pipe. It has no command that runs arbitrary programs or writes arbitrary registry paths.
"""

PIPE_NAME = r"\\.\pipe\appaudit-helper"
SESSION_NAME = "appaudit-live"
