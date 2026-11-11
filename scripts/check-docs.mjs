import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
// 从仓库根运行 node scripts/check-docs.mjs，扫描当前工作目录下的 Markdown。
const ignored = new Set(['.git', '.local', 'node_modules', 'bin', 'obj', 'artifacts', 'publish', 'TestResults', 'dist', '.umi', '.umi-production', '.turbopack', '.cache', 'coverage', 'test-results', 'playwright-report', 'App_Data', 'logs', 'run-data', 'imports', 'exports']);
let checked = 0;
const problems = [];
function visit(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (ignored.has(entry.name) || entry.isSymbolicLink()) continue;
    const name = resolve(path, entry.name);
    if (entry.isDirectory()) { visit(name); continue; }
    if (!name.endsWith('.md')) continue;
    const text = readFileSync(name, 'utf8');
    for (const match of text.matchAll(/\]\(([^)]+)\)/g)) {
      const target = match[1].split('#')[0].replace(/^<|>$/g, '');
      if (!target || /^[a-z]+:/i.test(target) || target.includes(' ') || target.startsWith('/')) continue;
      checked++;
      if (!existsSync(resolve(dirname(name), decodeURIComponent(target)))) problems.push(`${name}: ${target}`);
    }
  }
}
visit(process.cwd());
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log(`文档本地链接检查通过：${checked} 条。`);
