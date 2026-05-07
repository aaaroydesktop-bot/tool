#!/data/data/com.termux/files/usr/bin/bash

pkg update -y
pkg install python -y

pip install -r requirements.txt

chmod +x main.py

mv main.py $PREFIX/bin/mytool

echo "✅ Installed"