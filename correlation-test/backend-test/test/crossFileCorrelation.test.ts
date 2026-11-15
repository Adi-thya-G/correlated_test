import assert from 'node:assert';
import { scorePair, THRESHOLD } from '../services/correlationScore';

type Finding = Record<string, any>;

const cases: {
  name: string;
  a: Finding;
  b: Finding;
  sim: number;
  expect: 'cluster' | 'separate';
  mustNotHave?: string[];
}[] = [
  {
    name: 'same secret, different files, different tools, same commit and CWE',
    a: { tool: 'semgrep', ruleId: 'hardcoded-password', cwe: 'CWE-798', file: 'src/db/config.js', startLine: 1, function: null, git_commit_hash: 'abc123' },
    b: { tool: 'gitleaks', ruleId: 'generic-api-key', cwe: 'CWE-798', file: 'src/reports/config.js', startLine: 1, function: null, git_commit_hash: 'abc123' },
    sim: 0.82,
    expect: 'cluster',
  },
  {
    name: 'same CWE, different files, different commits, low similarity',
    a: { tool: 'semgrep', ruleId: 'hardcoded-password', cwe: 'CWE-798', file: 'src/db/config.js', startLine: 1, function: null, git_commit_hash: 'abc123' },
    b: { tool: 'gitleaks', ruleId: 'generic-api-key', cwe: 'CWE-798', file: 'src/reports/config.js', startLine: 1, function: null, git_commit_hash: 'def456' },
    sim: 0.5,
    expect: 'separate',
  },
  {
    name: 'same rule, different files, same tool, no commit or CWE',
    a: { tool: 'semgrep', ruleId: 'sql-injection', cwe: null, file: 'src/api/users.js', startLine: 2, function: 'getUser', git_commit_hash: null },
    b: { tool: 'semgrep', ruleId: 'sql-injection', cwe: null, file: 'src/admin/users.js', startLine: 2, function: 'getUser', git_commit_hash: null },
    sim: 0.3,
    expect: 'separate',
    mustNotHave: ['function'],
  },
  {
    name: 'same function name in different files (must not get function bonus)',
    a: { tool: 'semgrep', ruleId: 'sql-injection', cwe: 'CWE-89', file: 'src/api/users.js', startLine: 2, function: 'getUser', git_commit_hash: null },
    b: { tool: 'semgrep', ruleId: 'sql-injection', cwe: 'CWE-89', file: 'src/admin/users.js', startLine: 2, function: 'getUser', git_commit_hash: null },
    sim: 0.3,
    expect: 'separate',
    mustNotHave: ['function'],
  },
  {
    name: 'same file, same function, 5 lines apart, high similarity',
    a: { tool: 'semgrep', ruleId: 'sql-injection', cwe: 'CWE-89', file: 'src/api/users.js', startLine: 2, function: 'getUser', git_commit_hash: null },
    b: { tool: 'semgrep', ruleId: 'sql-injection', cwe: 'CWE-89', file: 'src/api/users.js', startLine: 7, function: 'getUser', git_commit_hash: null },
    sim: 0.7,
    expect: 'cluster',
  },
  {
    name: 'same file, 50 lines apart, same tool, high similarity',
    a: { tool: 'semgrep', ruleId: 'sql-injection', cwe: null, file: 'src/api/users.js', startLine: 2, function: null, git_commit_hash: null },
    b: { tool: 'semgrep', ruleId: 'sql-injection', cwe: null, file: 'src/api/users.js', startLine: 52, function: null, git_commit_hash: null },
    sim: 0.7,
    expect: 'separate',
    mustNotHave: ['line'],
  },
];

for (const c of cases) {
  const r = scorePair(c.a, c.b, c.sim);
  const got = r.score >= THRESHOLD ? 'cluster' : 'separate';
  console.log(`${got === c.expect ? 'PASS' : 'FAIL'} | ${c.name} | score=${r.score.toFixed(3)} | signals=[${r.signals.join(', ')}]`);

  assert.strictEqual(got, c.expect, `${c.name}: expected ${c.expect}, got ${got} (score ${r.score.toFixed(3)})`);
  for (const s of c.mustNotHave ?? []) {
    assert.ok(!r.signals.includes(s), `${c.name}: signal "${s}" should not be present`);
  }
}

console.log('all cross-file checks passed');
