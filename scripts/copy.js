import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const mail  = 'https://github.com/DWTechs/Toker.js';
const CRLF  = '\r\n';
const rel   = './';
const src   = `${rel}build/`;
const dest  = `${rel}dist/`;
const files = [
  {
    src:  `${rel}src/toker.d.ts`,
    dest: `${dest}toker.d.ts`
  },
  {
    src:  `${src}toker.mjs`,
    dest: `${dest}toker.js`
  },
];

mkdirSync(dest, { recursive: false });
const license = readFileSync(`${rel}LICENSE`);
for (const file of files) {
  const fileContent = readFileSync(file.src);
  writeFileSync(file.dest, `/*${CRLF}${license}${CRLF}${mail}${CRLF}*/${CRLF}${CRLF}${fileContent}`);
}