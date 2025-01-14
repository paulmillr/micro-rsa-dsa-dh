import * as fs from 'node:fs';
import * as zlib from 'node:zlib';
import { dirname, join as pathjoin } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha1 } from '@noble/hashes/sha1';
import { sha256, sha224 } from '@noble/hashes/sha256';
import { sha384, sha512, sha512_256, sha512_224 } from '@noble/hashes/sha512';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3';
export { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const jsonGZ = (path) => {
  const data = fs.readFileSync(pathjoin(__dirname, path));
  return JSON.parse(path.endsWith('.gz') ? zlib.gunzipSync(data) : data);
};

export const HASHES = {
  'SHA-1': sha1,
  'SHA-224': sha224,
  'SHA-256': sha256,
  'SHA-384': sha384,
  'SHA-512': sha512,
  'SHA-512/224': sha512_224,
  'SHA-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  SHAKE128: shake128,
  SHAKE256: shake256,
};

// TODO: unify with component parser
// This is generic parser, but component uses line separator inside tests
export function parseTestFile(filePath) {
  const data = fs.readFileSync(filePath, 'utf-8');
  const lines = data.split('\n').map((line) => line.trim());
  const groups = [];
  let curGroup = { tests: [] };
  let curTest = {};
  for (const l of lines) {
    if (l.startsWith('#')) continue;
    if (!l) {
      if (Object.keys(curTest).length > 0) {
        curGroup.tests = (curGroup.tests || []).concat(curTest);
        curTest = {};
      }
      continue;
    }
    if (l.startsWith('[') && l.endsWith(']')) {
      if (Object.keys(curGroup).length > 0 && Object.keys(curGroup.tests).length > 0) {
        groups.push(curGroup);
        curGroup = { tests: [] };
      }
      const [k, v] = l
        .slice(1, -1)
        .split(' = ')
        .map((part) => part.trim());
      curGroup[k] = v;
    } else if (l.includes(' = ')) {
      const [key, value] = l.split(' = ').map((part) => part.trim());
      curTest[key] = value;
    }
  }
  if (Object.keys(curTest).length > 0) curGroup.tests = (curGroup.tests || []).concat(curTest);
  if (Object.keys(curGroup).length > 0) groups.push(curGroup);
  return groups;
}
