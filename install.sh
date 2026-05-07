#!/bin/bash

# কালার কোড
GREEN="\e[1;32m"
BLUE="\e[1;34m"
RED="\e[1;31m"
RESET="\e[0m"

echo -e "${BLUE}[*] Updating Termux repositories...${RESET}"
pkg update -y && pkg upgrade -y

echo -e "${BLUE}[*] Installing required packages (Python, Git)...${RESET}"
pkg install python git -y

echo -e "${BLUE}[*] Installing Python modules from requirements.txt...${RESET}"
pip install -r requirements.txt

echo -e "${BLUE}[*] Making main.py executable...${RESET}"
chmod +x main.py

echo -e "${BLUE}[*] Installing 'netscan' to global binary path...${RESET}"
# ফাইলটিকে Termux এর bin ফোল্ডারে 'netscan' নামে কপি করা হচ্ছে
cp main.py $PREFIX/bin/netscan

# গ্লোবাল কমান্ডটিকেও এক্সিকিউটেবল করা হচ্ছে
chmod +x $PREFIX/bin/netscan

echo -e "${GREEN}✅ Setup Completed Successfully!${RESET}"
echo -e "${GREEN}🎉 You can now type '${BLUE}netscan${GREEN}' from anywhere in Termux to launch the tool!${RESET}"