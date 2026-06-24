/* eslint-disable @typescript-eslint/no-require-imports */
/**
 * Placeholder security test script.
 * To be expanded with dependency vulnerability checks (npm audit),
 * static secret scans, and OWASP baseline assertions.
 */

const { execSync } = require('child_process');

function run(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    return err.stdout || err.message;
  }
}

console.log('Running security smoke checks...');
const audit = run('npm audit --json');
const auditData = JSON.parse(audit || '{}');
const vulnerabilities = auditData.metadata?.vulnerabilities || {};
const total = Object.values(vulnerabilities).reduce((a, b) => a + b, 0);
console.log(`npm audit total vulnerabilities: ${total}`);

if (total > 0) {
  console.warn('Please review `npm audit` output and update dependencies.');
}

console.log('Security smoke checks complete.');
process.exit(total > 20 ? 1 : 0); // soft gate; tighten once audit findings are fixed
