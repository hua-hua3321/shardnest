#!/usr/bin/env bash
# 发布 @wallet-service/* 到 npm（依赖拓扑顺序）
# 用法: bash scripts/publish.sh [--dry-run]
set -euo pipefail
cd "$(dirname "$0")/.."

DRY="${1:-}"
PACKAGES=(core signer verify-sdk protocol cli mcp-server)

# 版本号映射（Bash 3.2 兼容：macOS 默认 Bash 3.2 不支持 declare -A 关联数组，
# 用普通函数 + case 替代）
version_of() {
  case "$1" in
    core) echo "0.1.0" ;;
    signer) echo "0.2.0" ;;
    cli) echo "0.2.0" ;;
    mcp-server) echo "0.3.0" ;;
    protocol) echo "0.3.0" ;;
    verify-sdk) echo "0.3.0" ;;
    *) echo "0.0.0" ;;
  esac
}

# ── 备份原始 package.json（发布后还原，保留 workspace:* 供本地开发）──
BACKUP_DIR="$(mktemp -d)"
for p in "${PACKAGES[@]}"; do cp "packages/$p/package.json" "$BACKUP_DIR/$p.json"; done
trap 'for p in "${PACKAGES[@]}"; do cp "$BACKUP_DIR/$p.json" "packages/$p/package.json"; done; echo "package.json 已还原"' EXIT

# ── workspace:* → 版本号 ──
for p in "${PACKAGES[@]}"; do
  python3 - "$p" << 'PY'
import json, sys
name = sys.argv[1]
mapping = {'core':'0.1.0','signer':'0.2.0','cli':'0.2.0','mcp-server':'0.3.0','protocol':'0.3.0','verify-sdk':'0.3.0'}
pkg_path = f'packages/{name}/package.json'
with open(pkg_path) as f:
    pkg = json.load(f)
for dep_type in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
    deps = pkg.get(dep_type) or {}
    for k in list(deps):
        if deps[k] == 'workspace:*':
            sub = k.replace('@wallet-service/', '')
            if sub not in mapping:
                raise SystemExit(f'unknown workspace dep {k} in {name}')
            deps[k] = f'^{mapping[sub]}'
    if deps:
        pkg[dep_type] = deps
with open(pkg_path, 'w') as f:
    json.dump(pkg, f, indent=2, ensure_ascii=False)
    f.write('\n')
print(f'resolved workspace:* in {name}')
PY
done

# ── 逐包发布（prepublishOnly 自动构建）──
for p in "${PACKAGES[@]}"; do
  echo "=== @wallet-service/$p@$(version_of "$p") ==="
  (cd "packages/$p" && npm publish --access public --registry https://registry.npmjs.org ${DRY:+--dry-run})
done
echo "全部发布完成 ✅"
