#!/usr/bin/env bash
#
# 构建 privacy-filter 二进制并安装到 cc-switch 的打包资源目录。
#
# 用法：
#   ./scripts/build-privacy-filter.sh [privacy-filter 源码目录]
#
#   PF_SRC=/path/to/privacy-filter ./scripts/build-privacy-filter.sh
#   TARGETS="darwin/arm64 darwin/amd64" ./scripts/build-privacy-filter.sh
#
# 默认只构建当前平台；交叉编译用 TARGETS 指定 "GOOS/GOARCH" 列表。
# 产物：
#   src-tauri/resources/privacy-filter-<os>-<arch>[.exe]
#   src-tauri/resources/gitleaks.toml

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RESOURCES_DIR="$REPO_ROOT/src-tauri/resources"

# privacy-filter 源码位置：参数 > 环境变量 > 仓库同级目录
PF_SRC="${1:-${PF_SRC:-$REPO_ROOT/../privacy-filter-main}}"

if [[ ! -f "$PF_SRC/go.mod" ]]; then
  echo "error: privacy-filter source not found at: $PF_SRC" >&2
  echo "  clone it first, or pass the path: ./scripts/build-privacy-filter.sh /path/to/privacy-filter" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "error: go toolchain not found (https://go.dev/dl/)" >&2
  exit 1
fi

# 默认构建当前平台
host_target="$(go env GOOS)/$(go env GOARCH)"
TARGETS="${TARGETS:-$host_target}"

mkdir -p "$RESOURCES_DIR"

for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  [[ "$goos" == "windows" ]] && ext=".exe"

  out="$RESOURCES_DIR/privacy-filter-$goos-$goarch$ext"
  echo "building $out ..."
  (cd "$PF_SRC" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/http)
done

# gitleaks 规则集：缺失时 privacy-filter 会回退到内置兜底规则，
# 打包完整规则集以获得最佳的密钥检测能力。
cp "$PF_SRC/rules/gitleaks.toml" "$RESOURCES_DIR/gitleaks.toml"
echo "copied gitleaks.toml"

echo "done. resources:"
ls -lh "$RESOURCES_DIR"
