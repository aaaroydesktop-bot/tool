#!/data/data/com.termux/files/usr/bin/bash

# =========================================
# NETSCAN INSTALLER FOR TERMUX
# =========================================

# =========================================
# COLORS
# =========================================

GREEN="\e[1;32m"
BLUE="\e[1;34m"
RED="\e[1;31m"
YELLOW="\e[1;33m"
CYAN="\e[1;36m"
RESET="\e[0m"

clear

# =========================================
# BANNER
# =========================================

echo -e "${CYAN}"
echo "=============================================="
echo "             NETSCAN INSTALLER"
echo "=============================================="
echo -e "${RESET}"

# =========================================
# STORAGE PERMISSION
# =========================================

echo -e "${YELLOW}[*] Setting Up Storage Permission...${RESET}"

termux-setup-storage

sleep 2

# =========================================
# UPDATE TERMUX
# =========================================

echo -e "${YELLOW}[*] Updating Packages...${RESET}"

pkg update -y && pkg upgrade -y

# =========================================
# INSTALL REPOSITORIES
# =========================================

echo -e "${YELLOW}[*] Installing Repositories...${RESET}"

pkg install root-repo -y
pkg install unstable-repo -y

# =========================================
# INSTALL REQUIRED PACKAGES
# =========================================

echo -e "${YELLOW}[*] Installing Required Packages...${RESET}"

packages=(
python
python-pip
git
clang
make
cmake
openssl
openssl-tool
libffi
rust
wget
curl
nano
vim
termux-api
nmap
net-tools
dnsutils
traceroute
tsu
)

for pkgname in "${packages[@]}"
do

    echo -e "${BLUE}[+] Installing ${pkgname}...${RESET}"

    pkg install -y "$pkgname"

done

# =========================================
# UPGRADE PIP
# =========================================

echo -e "${YELLOW}[*] Upgrading Pip...${RESET}"

python -m pip install --upgrade pip wheel setuptools

# =========================================
# INSTALL PYTHON LIBRARIES
# =========================================

echo -e "${YELLOW}[*] Installing Python Libraries...${RESET}"

pip install --no-cache-dir -r requirements.txt

# =========================================
# CREATE DIRECTORIES
# =========================================

echo -e "${YELLOW}[*] Creating Directories...${RESET}"

mkdir -p reports
mkdir -p logs
mkdir -p database
mkdir -p plugins

# =========================================
# DATABASE CHECK
# =========================================

if [ ! -f database/toolkit.db ]; then

    touch database/toolkit.db

fi

# =========================================
# EXECUTABLE PERMISSION
# =========================================

echo -e "${YELLOW}[*] Setting Executable Permissions...${RESET}"

chmod +x main.py

# =========================================
# CREATE LAUNCHER
# =========================================

echo -e "${YELLOW}[*] Creating Global Command...${RESET}"

cat > $PREFIX/bin/netscan << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

cd ~/TOOL

python main.py
EOF

chmod +x $PREFIX/bin/netscan

# =========================================
# INSTALL COMPLETE
# =========================================

clear

echo -e "${GREEN}"
echo "=============================================="
echo "         NETSCAN INSTALL COMPLETE"
echo "=============================================="
echo -e "${RESET}"

echo -e "${GREEN}[✓] Toolkit Installed Successfully${RESET}"

echo -e "${CYAN}"
echo "Run Tool Using:"
echo -e "${YELLOW}netscan${RESET}"

echo -e "${CYAN}"
echo "Project Folder:"
echo -e "${YELLOW}~/TOOL${RESET}"

echo -e "${GREEN}"
echo "Features Installed:"
echo "✓ Port Scanner"
echo "✓ Ping Tools"
echo "✓ DNS Lookup"
echo "✓ GeoIP"
echo "✓ Speed Test"
echo "✓ Local Network Scan"
echo "✓ Traceroute"
echo "✓ Vendor Detection"
echo "✓ AI Assistant"
echo "✓ Plugin System"
echo -e "${RESET}"