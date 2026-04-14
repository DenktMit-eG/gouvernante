#!/usr/bin/env bash
# licenses.sh — Generate a license report from vendored dependencies.
#
# Scans vendor/ for LICENSE, COPYING, and NOTICE files, identifies each
# dependency's license type, and writes a Markdown report.
#
# Usage:
#   ./scripts/licenses.sh [OUTPUT_FILE]
#
# If OUTPUT_FILE is omitted, writes to dist/reports/licenses.md.

set -euo pipefail

VENDOR_DIR="vendor"
OUTPUT="${1:-dist/reports/licenses.md}"

if [ ! -d "$VENDOR_DIR" ]; then
    echo "error: vendor/ directory not found. Run 'go mod vendor' first." >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

# Detect license type from file content.
detect_license() {
    local file="$1"
    local content
    content=$(head -20 "$file" 2>/dev/null || true)
    if echo "$content" | grep -qi "MIT License\|Permission is hereby granted"; then
        echo "MIT"
    elif echo "$content" | grep -qi "Apache License"; then
        echo "Apache-2.0"
    elif echo "$content" | grep -qi "BSD \(3-Clause\)\|Redistribution and use in source and binary"; then
        echo "BSD-3-Clause"
    elif echo "$content" | grep -qi "BSD \(2-Clause\)\|Simplified BSD"; then
        echo "BSD-2-Clause"
    elif echo "$content" | grep -qi "ISC License\|ISC license"; then
        echo "ISC"
    elif echo "$content" | grep -qi "Mozilla Public License"; then
        echo "MPL-2.0"
    else
        echo "Unknown"
    fi
}

# Collect all license files.
license_files=$(find "$VENDOR_DIR" -maxdepth 6 \
    \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
    -not -path '*/testdata/*' | sort)

if [ -z "$license_files" ]; then
    echo "warning: no license files found in vendor/." >&2
    exit 0
fi

# Build the report.
{
    echo "# Third-Party License Report"
    echo ""
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "All external dependencies are vendored in \`vendor/\`. Each dependency's"
    echo "license file is included verbatim in the vendor tree."
    echo ""
    echo "## Summary"
    echo ""
    echo "| Module | License | File |"
    echo "|--------|---------|------|"

    while IFS= read -r license_file; do
        # Derive module path: strip vendor/ prefix and the license filename.
        module_path=$(dirname "$license_file" | sed 's|^vendor/||')
        license_type=$(detect_license "$license_file")
        rel_file=$(echo "$license_file" | sed 's|^vendor/||')
        echo "| \`$module_path\` | $license_type | \`$rel_file\` |"
    done <<< "$license_files"

    echo ""
    echo "## Full License Texts"
    echo ""

    while IFS= read -r license_file; do
        module_path=$(dirname "$license_file" | sed 's|^vendor/||')
        echo "### $module_path"
        echo ""
        echo '```'
        cat "$license_file"
        echo '```'
        echo ""
    done <<< "$license_files"
} > "$OUTPUT"

echo "License report written to $OUTPUT"
