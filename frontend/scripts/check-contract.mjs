import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..', '..');
const backendEnums = readFileSync(resolve(repoRoot, 'backend', 'app', 'schemas', 'enums.py'), 'utf8');
const frontendCatalog = readFileSync(resolve(repoRoot, 'frontend', 'src', 'domain', 'entityCatalog.ts'), 'utf8');

const entityClass = backendEnums.match(/class EntityType[\s\S]*?(?=\n\nclass )/)?.[0];
if (!entityClass) throw new Error('Could not locate backend EntityType enum');

const backendTypes = [...entityClass.matchAll(/^\s{4}[A-Z_]+\s*=\s*"([A-Z_]+)"/gm)].map(match => match[1]);
const catalogBlock = frontendCatalog.match(/export const ENTITY_CATALOG = \{([\s\S]*?)\n\} satisfies/)?.[1];
if (!catalogBlock) throw new Error('Could not locate frontend ENTITY_CATALOG');
const frontendTypes = [...catalogBlock.matchAll(/^\s{2}([A-Z_]+):/gm)].map(match => match[1]);

const missing = backendTypes.filter(type => !frontendTypes.includes(type));
const stale = frontendTypes.filter(type => !backendTypes.includes(type));
if (missing.length || stale.length) {
  throw new Error(`Entity contract mismatch. Missing in frontend: ${missing.join(', ') || 'none'}. Stale in frontend: ${stale.join(', ') || 'none'}.`);
}

console.log(`Entity contract OK: ${backendTypes.length} backend entity types mapped.`);
