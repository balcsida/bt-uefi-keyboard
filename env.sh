# Source from bash:  . ./env.sh
# Sets up the EDK2 build environment for this workspace (edk2 checkout + BtKbPkg).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WORKSPACE="$ROOT"
export PACKAGES_PATH="$ROOT/edk2:$ROOT"
export EDK_TOOLS_PATH="$ROOT/edk2/BaseTools"
export NASM_PREFIX="$ROOT/tools/local/bin/"
export PATH="$ROOT/tools/local/bin:$PATH"
pushd "$ROOT/edk2" >/dev/null && . ./edksetup.sh >/dev/null && popd >/dev/null
