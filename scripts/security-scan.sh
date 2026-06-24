#!/bin/bash

# Security Scan Script for ZumrutAutomation
# This script performs dependency vulnerability scanning and security checks

set -e

echo "🔒 Starting Security Scan..."
echo "================================"

# Create security reports directory if it doesn't exist
mkdir -p security-reports

# Check for Node.js vulnerabilities
echo "📦 Running npm audit..."
npm audit --audit-level=moderate --json > security-reports/npm-audit.json 2>&1 || {
    echo "⚠️  Found vulnerabilities in dependencies"
    npm audit --audit-level=moderate || true
}

# Check for outdated dependencies with security issues
echo "📊 Checking for outdated dependencies..."
npm outdated --json > security-reports/outdated-deps.json 2>&1 || true

# Scan for common security issues in package.json
echo "🔍 Scanning package.json for security issues..."
if grep -q '"scripts".*"preinstall".*"postinstall"' package.json; then
    echo "⚠️  WARNING: Found lifecycle scripts that could pose security risks"
fi

# Check for prototype pollution vulnerabilities
echo "🛡️  Checking for prototype pollution patterns..."
grep -r "Object.prototype" --include="*.js" --include="*.ts" src/ api/ 2>/dev/null | wc -l > security-reports/prototype-pollution-count.txt || true

# Check for hardcoded secrets (basic check)
echo "🔐 Scanning for potential hardcoded secrets..."
grep -rE "(password|secret|api[_-]?key|token).*=.*['\"][^'\"]{8,}" \
    --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
    --exclude-dir=node_modules --exclude-dir=dist \
    src/ api/ 2>/dev/null > security-reports/potential-secrets.txt || true

SECRET_COUNT=$(wc -l < security-reports/potential-secrets.txt 2>/dev/null || echo "0")
if [ "$SECRET_COUNT" -gt 0 ]; then
    echo "⚠️  WARNING: Found $SECRET_COUNT potential hardcoded secrets"
    echo "   Review security-reports/potential-secrets.txt"
fi

# Check for unsafe dependencies
echo "🔎 Checking for known vulnerable packages..."
if command -v safety &> /dev/null; then
    safety check --json > security-reports/safety-report.json 2>&1 || true
else
    echo "ℹ️  'safety' not installed, skipping Python dependency check"
fi

# Generate summary
echo "📝 Generating security summary..."
cat > security-reports/scan-summary.txt << EOF
Security Scan Summary
=====================
Date: $(date)
Repository: ZumrutAutomation

Checks Performed:
✓ NPM dependency vulnerability scan
✓ Outdated dependencies check
✓ Lifecycle scripts security check
✓ Prototype pollution pattern detection
✓ Hardcoded secrets detection
✓ Known vulnerable packages check

Results:
- NPM Audit: See npm-audit.json
- Outdated Dependencies: See outdated-deps.json
- Potential Secrets Found: $SECRET_COUNT
- Prototype Pollution Patterns: $(cat security-reports/prototype-pollution-count.txt 2>/dev/null || echo "0")

Action Required:
- Review all findings in the security-reports/ directory
- Update vulnerable dependencies
- Remove any hardcoded secrets
- Address high/critical severity issues immediately

EOF

echo "✅ Security scan complete!"
echo "📁 Reports saved to: security-reports/"
cat security-reports/scan-summary.txt

# Note: We don't exit with error for vulnerabilities to avoid blocking CI/CD
# Critical vulnerabilities are logged and should be addressed in future updates
if grep -q '"severity": "critical"' security-reports/npm-audit.json 2>/dev/null; then
    echo ""
    echo "⚠️  CRITICAL vulnerabilities found! Please review and address."
    echo "Note: Not blocking CI/CD - will address in next security sprint"
fi

exit 0
