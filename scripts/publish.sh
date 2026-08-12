#!/usr/bin/env bash
# 发布 @wallet-services/* 到 npm（依赖拓扑顺序）
# 用法: bash scripts/publish.sh [--dry-run]
set -euo pipefail
cd "$(dirname "$0")/.."

DRY="${1:-}"
PACKAGES=(core signer verify-sdk protocol cli mcp-server)

# 版本号从 package.json 动态读取（零硬编码）
version_of() {
  node -e "console.log(require('./packages/$1/package.json').version)"
}

# ── 备份原始 package.json（发布后还原，保留 workspace:* 供本地开发）──
BACKUP_DIR="$(mktemp -d)"
for p in "${PACKAGES[@]}"; do cp "packages/$p/package.json" "$BACKUP_DIR/$p.json"; done
trap 'for p in "${PACKAGES[@]}"; do cp "$BACKUP_DIR/$p.json" "packages/$p/package.json"; done; echo "package.json 已还原"' EXIT

# ── workspace:* → 版本号（从各包 package.json 动态读取）──
for p in "${PACKAGES[@]}"; do
  python3 - "$p" << 'PY'
import json, sys, os
name = sys.argv[1]
pkg_path = f'packages/{name}/package.json'
with open(pkg_path) as f:
    pkg = json.load(f)
# 动态构建版本映射：从各包 package.json 读取当前 version
mapping = {}
for d in os.listdir('packages'):
    p = os.path.join('packages', d, 'package.json')
    if os.path.isfile(p):
        with open(p) as f:
            mapping[json.load(f)['name'].replace('@wallet-services/', '')] = json.load(open(p))['version']
for dep_type in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
    deps = pkg.get(dep_type) or {}
    for k in list(deps):
        if deps[k] == 'workspace:*':
            sub = k.replace('@wallet-services/', '')
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

# ── 逐包发布（prepublishOnly 自动构建；版本已存在则跳过，幂等）──
for p in "${PACKAGES[@]}"; do
  ver=$(version_of "$p")
  if npm view "@wallet-services/$p@$ver" version --registry https://registry.npmjs.org > /dev/null 2>&1; then
    echo "=== @wallet-services/$p@$ver 已存在，跳过 ==="
    continue
  fi
  echo "=== @wallet-services/$p@$ver ==="
  (cd "packages/$p" && npm publish --access public --registry https://registry.npmjs.org ${DRY:+--dry-run})
done
echo "全部发布完成 ✅"
