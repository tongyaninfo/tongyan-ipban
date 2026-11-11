import { cp, mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const frontendDirectory = resolve(scriptDirectory, '..');
const sourceDirectory = resolve(frontendDirectory, 'dist');
const targetDirectory = resolve(
  frontendDirectory,
  '..',
  'backend',
  'src',
  'IpBan.Api',
  'wwwroot',
);

// wwwroot 是前端构建输出目录。每次构建先清理旧 hash 资源，避免已移除的模板页面仍能通过旧静态文件访问。
await rm(targetDirectory, { recursive: true, force: true });
await mkdir(targetDirectory, { recursive: true });
await cp(sourceDirectory, targetDirectory, { recursive: true, force: true });
console.log(`前端构建产物已复制到 ${targetDirectory}`);
