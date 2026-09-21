import fs from 'node:fs';
import path from 'node:path';

const buildDirectory = path.resolve('build');
fs.mkdirSync(buildDirectory, { recursive: true });

for (const file of ['action.yml', 'README.md']) {
  fs.copyFileSync(file, path.join(buildDirectory, file));
}

fs.copyFileSync('src/main.js', path.join(buildDirectory, 'main.js'));
