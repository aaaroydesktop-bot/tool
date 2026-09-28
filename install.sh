#!/data/data/com.termux/files/usr/bin/bash
#
# NetScan installer for Termux.
#
# Design goals, learned the hard way on Android:
#   * never abort the whole install because one *optional* package is missing
#   * never add third-party repos (root-repo/unstable-repo break package resolution)
#   * never install a compiler toolchain unless something actually needs building
#   * be idempotent: safe to re-run at any time
#
# Usage:
#   bash install.sh                 full install
#   bash install.sh --no-update     skip 'pkg update'
#   bash install.sh --no-optional   skip optional tools (nmap, traceroute, ...)
#   bash install.sh --uninstall     remove the global command

set -u

GREEN="\e[1;32m"; BLUE="\e[1;34m"; RED="\e[1;31m"
YELLOW="\e[1;33m"; CYAN="\e[1;36m"; DIM="\e[2m"; RESET="\e[0m"

DO_UPDATE=1
DO_OPTIONAL=1
DO_UNINSTALL=0

for arg in "$@"; do
    case "$arg" in
        --no-update)   DO_UPDATE=0 ;;
        --no-optional) DO_OPTIONAL=0 ;;
        --uninstall)   DO_UNINSTALL=1 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo -e "${RED}unknown option: $arg${RESET}" >&2
            exit 2 ;;
    esac
done

TOOL_PATH="$(cd "$(dirname "$0")" && pwd)"
PREFIX_BIN="${PREFIX:-/data/data/com.termux/files/usr}/bin"

step()  { echo -e "${YELLOW}[*]${RESET} $1"; }
good()  { echo -e "${GREEN}[+]${RESET} $1"; }
skip()  { echo -e "${DIM}[-] $1${RESET}"; }
fail()  { echo -e "${RED}[x]${RESET} $1"; }

# --------------------------------------------------------------------------
# PREFLIGHT
# --------------------------------------------------------------------------

clear
echo -e "${CYAN}=============================================="
echo "              NETSCAN INSTALLER"
echo -e "==============================================${RESET}"
echo

if [ "$DO_UNINSTALL" = "1" ]; then
    if [ -f "$PREFIX_BIN/netscan" ]; then
        rm -f "$PREFIX_BIN/netscan"
        good "Removed $PREFIX_BIN/netscan"
    else
        skip "No global command to remove."
    fi
    echo
    echo "Project files were left untouched at: $TOOL_PATH"
    exit 0
fi

if [ ! -f "$TOOL_PATH/main.py" ]; then
    fail "main.py not found in $TOOL_PATH"
    echo "    Run this script from inside the NetScan checkout."
    exit 1
fi

if [ -z "${TERMUX_VERSION:-}" ] && [ ! -d "/data/data/com.termux" ]; then
    fail "This installer targets Termux."
    echo "    On Linux/macOS/Windows instead run:"
    echo "        pip install -r requirements.txt && python main.py"
    exit 1
fi

good "Termux detected — $(uname -m), Android $(getprop ro.build.version.release 2>/dev/null || echo '?')"
echo -e "${DIM}    project: $TOOL_PATH${RESET}"
echo

# --------------------------------------------------------------------------
# STORAGE + REPOSITORIES
# --------------------------------------------------------------------------

step "Requesting shared-storage access (needed to export reports)..."
if [ -d "$HOME/storage/shared" ]; then
    skip "Storage already configured."
else
    termux-setup-storage 2>/dev/null || skip "termux-setup-storage unavailable — press 'Allow' manually later."
fi

if [ "$DO_UPDATE" = "1" ]; then
    step "Updating package lists..."
    pkg update -y >/dev/null 2>&1 || fail "pkg update failed — continuing anyway."
else
    skip "Skipping pkg update (--no-update)."
fi

# --------------------------------------------------------------------------
# PACKAGES
# --------------------------------------------------------------------------

REQUIRED_PKGS="python python-pip git openssl libffi termux-api"
OPTIONAL_PKGS="nmap iproute2 dnsutils whois curl"

step "Installing required packages: $REQUIRED_PKGS"
# shellcheck disable=SC2086
if pkg install -y $REQUIRED_PKGS; then
    good "Required packages installed."
else
    fail "Some required packages failed — retrying one by one..."
    for pkgname in $REQUIRED_PKGS; do
        pkg install -y "$pkgname" >/dev/null 2>&1 || fail "  $pkgname"
    done
fi

if command -v python >/dev/null 2>&1; then
    good "python $(python --version 2>&1 | awk '{print $2}')"
else
    fail "python is still unavailable — cannot continue."
    exit 1
fi

if [ "$DO_OPTIONAL" = "1" ]; then
    step "Installing optional tools (best effort): $OPTIONAL_PKGS"
    for pkgname in $OPTIONAL_PKGS; do
        if pkg list-installed 2>/dev/null | grep -q "^${pkgname}/"; then
            skip "$pkgname already installed"
            continue
        fi
        if pkg install -y "$pkgname" >/dev/null 2>&1; then
            good "$pkgname"
        else
            skip "$pkgname unavailable (that feature degrades gracefully)"
        fi
    done
else
    skip "Skipping optional tools (--no-optional)."
fi

# --------------------------------------------------------------------------
# PYTHON LIBRARIES
# --------------------------------------------------------------------------

step "Upgrading pip..."
python -m pip install --upgrade pip wheel setuptools >/dev/null 2>&1 || \
    skip "pip self-upgrade failed (not fatal)."

step "Installing Python requirements..."
if python -m pip install --no-cache-dir -r "$TOOL_PATH/requirements.txt"; then
    good "Requirements installed."
elif python -m pip install --no-cache-dir --break-system-packages \
        -r "$TOOL_PATH/requirements.txt"; then
    good "Requirements installed (with --break-system-packages)."
else
    fail "pip install failed. Install the essentials by hand:"
    echo "    python -m pip install --no-cache-dir rich requests urllib3 python-whois"
fi

# --------------------------------------------------------------------------
# RUNTIME DIRECTORIES + DATABASE
# --------------------------------------------------------------------------

step "Preparing runtime directories..."
mkdir -p "$TOOL_PATH/reports" "$TOOL_PATH/logs" "$TOOL_PATH/database" "$TOOL_PATH/plugins"
[ -f "$TOOL_PATH/database/toolkit.db" ] || : > "$TOOL_PATH/database/toolkit.db"
good "reports/ logs/ database/ plugins/"

chmod +x "$TOOL_PATH/main.py" 2>/dev/null
[ -f "$TOOL_PATH/install.sh" ] && chmod +x "$TOOL_PATH/install.sh"
[ -f "$TOOL_PATH/bin/netscan" ] && chmod +x "$TOOL_PATH/bin/netscan"

# --------------------------------------------------------------------------
# GLOBAL COMMAND
# --------------------------------------------------------------------------

step "Installing the 'netscan' command..."

if [ -f "$TOOL_PATH/bin/netscan" ] && command -v sed >/dev/null 2>&1; then
    sed "s|__NETSCAN_HOME__|$TOOL_PATH|g" "$TOOL_PATH/bin/netscan" > "$PREFIX_BIN/netscan"
else
    cat > "$PREFIX_BIN/netscan" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$TOOL_PATH" || exit 1
exec python main.py "\$@"
EOF
fi

chmod +x "$PREFIX_BIN/netscan"

if [ -x "$PREFIX_BIN/netscan" ]; then
    good "Installed: $PREFIX_BIN/netscan"
    INSTALL_STATUS="SUCCESS"
else
    fail "Could not write $PREFIX_BIN/netscan"
    INSTALL_STATUS="FAILED"
fi

# --------------------------------------------------------------------------
# VERIFY
# --------------------------------------------------------------------------

step "Running a self-check..."
echo
(cd "$TOOL_PATH" && python main.py doctor) || \
    fail "Self-check reported problems — see the table above."
echo

# --------------------------------------------------------------------------
# SUMMARY
# --------------------------------------------------------------------------

if [ "$INSTALL_STATUS" = "SUCCESS" ]; then
    echo -e "${GREEN}=============================================="
    echo "        NETSCAN INSTALL COMPLETE"
    echo -e "==============================================${RESET}"
else
    echo -e "${RED}=============================================="
    echo "        NETSCAN INSTALL FAILED"
    echo -e "==============================================${RESET}"
fi

echo
echo -e "${CYAN}Start the tool:${RESET}"
echo -e "  ${YELLOW}netscan${RESET}                     interactive menu"
echo -e "  ${YELLOW}netscan --help${RESET}              all commands"
echo -e "  ${YELLOW}netscan scan 192.168.1.1${RESET}    quick port scan"
echo -e "  ${YELLOW}netscan local --names${RESET}       devices on your Wi-Fi"
echo -e "  ${YELLOW}netscan doctor${RESET}              diagnose setup"
echo
echo -e "${CYAN}Export a report:${RESET}"
echo -e "  ${YELLOW}netscan scan example.com -o scan.html -f html${RESET}"
echo
echo -e "${DIM}Project: $TOOL_PATH${RESET}"
echo -e "${DIM}Uninstall command with: bash install.sh --uninstall${RESET}"
echo
