import { should } from 'micro-should';

import './primality.test.js';
import './rsa.test.js';
import './dh.test.js';
import './dsa.test.js';
import './elgamal.test.js';

should.runWhen(import.meta.url);
