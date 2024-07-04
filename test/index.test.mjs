import { should } from 'micro-should';

import './primality.test.mjs';
import './rsa.test.mjs';
import './dh.test.mjs';
import './dsa.test.mjs';
import './elgamal.test.mjs';

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
