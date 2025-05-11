import os
import subprocess
import capture_analyzer  # Import your script to access __version__

# Get the version
version = capture_analyzer.__version__

# Define the output executable name
exe_name = f"capture_analyzer_{version}"

# Build the command for pyinstaller
command = [
    "pyinstaller",
    "--onefile",
    f"--name={exe_name}",
    "main.py"
]

# Run the command
subprocess.run(command)

print(f"Executable generated: dist/{exe_name}")
