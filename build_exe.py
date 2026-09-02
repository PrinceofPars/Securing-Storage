import PyInstaller.__main__
import customtkinter
import os
import shutil
from pathlib import Path

# Get customtkinter path for PyInstaller
customtkinter_path = os.path.dirname(customtkinter.__file__)

# Define paths
base_dir = Path(__file__).parent.resolve()
client_dir = base_dir / 'usb_client'
dist_dir = base_dir / 'dist'

# Clean previous builds
if dist_dir.exists():
    shutil.rmtree(dist_dir)

print(f"Building from {client_dir}...")
print(f"Adding customtkinter from {customtkinter_path}")

PyInstaller.__main__.run([
    str(client_dir / 'gui.py'),
    '--name=USB_Killswitch',
    '--windowed',
    '--onedir',  # creating a folder is safer for large libs, but user might want --onefile. Let's do --onedir for stability.
    f'--add-data={customtkinter_path};customtkinter/',
    '--clean',
    '--noconfirm',
    f'--distpath={dist_dir}'
])

print("\n--- Build Complete! ---")
print(f"Executable is located in: {dist_dir}\\USB_Killswitch\\USB_Killswitch.exe")
