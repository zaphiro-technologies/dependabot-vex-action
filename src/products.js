/*
 * Copyright 2026 Zaphiro Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import fs from 'node:fs';
import { absolute, fail, input } from './runtime.js';

function section(text, heading) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(line => line.trim() === heading);
  if (start === -1) return '';
  const result = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim().startsWith('[')) break;
    result.push(line);
  }
  return result.join('\n');
}

function tomlString(text, key) {
  const line = text.split(/\r?\n/).find(item => {
    const trimmed = item.trim();
    const separator = trimmed.indexOf('=');
    return separator !== -1 && trimmed.slice(0, separator).trim() === key;
  });
  if (!line) return '';
  const value = line.slice(line.indexOf('=') + 1).trim();
  const quote = value[0];
  return (quote === '"' || quote === "'") && value.endsWith(quote)
    ? value.slice(1, -1)
    : '';
}

function deriveSourcePurls(runtime) {
  const purls = [];
  const goMod = absolute(runtime, 'go.mod');
  if (fs.existsSync(goMod)) {
    const module = fs.readFileSync(goMod, 'utf8')
      .split(/\r?\n/)
      .find(line => line.trim().startsWith('module '))
      ?.trim()
      .slice('module '.length)
      .trim();
    if (module) purls.push(`pkg:golang/${module}`);
  }

  const pyproject = absolute(runtime, 'pyproject.toml');
  if (fs.existsSync(pyproject)) {
    const text = fs.readFileSync(pyproject, 'utf8');
    const name = tomlString(section(text, '[project]'), 'name')
      || tomlString(section(text, '[tool.poetry]'), 'name');
    if (name) purls.push(`pkg:pypi/${name.replaceAll(/[-_.]+/g, '-').toLowerCase()}`);
  }

  const packageJson = absolute(runtime, 'package.json');
  if (fs.existsSync(packageJson)) {
    try {
      const name = JSON.parse(fs.readFileSync(packageJson, 'utf8')).name;
      const packageName = name?.startsWith('@') ? `%40${name.slice(1)}` : name;
      if (packageName) purls.push(`pkg:npm/${packageName}`);
    } catch (error) {
      console.warn(`Warning: unable to parse package.json: ${error.message}`);
    }
  }
  return purls;
}

export function productPurls(runtime) {
  const explicit = input('product-purls')
    .split(/\r?\n/)
    .map(value => value.trim())
    .filter(Boolean);
  if (explicit.length) {
    console.log('Using explicitly configured product PURLs');
    return [...new Set(explicit)];
  }

  const imageName = (input('image-name') || runtime.repo).toLowerCase();
  if (!imageName || /\s|:/.test(imageName)) {
    fail('image-name must be non-empty and must not contain whitespace or :');
  }
  const imageRepository = `ghcr.io/${runtime.owner.toLowerCase()}/${imageName}`;
  const encodedRepository = imageRepository.replaceAll('/', '%2F');
  const derived = [`pkg:oci/${imageName}?repository_url=${encodedRepository}`, ...deriveSourcePurls(runtime)];
  console.log('Using automatically derived product PURLs:');
  for (const purl of new Set(derived)) console.log(`  ${purl}`);
  return [...new Set(derived)];
}
