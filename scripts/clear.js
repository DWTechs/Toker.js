import { rmSync } from 'node:fs';
const options = { recursive: true, force: true };
rmSync('./build/', options);
rmSync('./dist/', options);
