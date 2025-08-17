import { should } from 'micro-should';

import './dh.test.ts';
import './dsa.test.ts';
import './elgamal.test.ts';
import './primality.test.ts';
import './rsa.test.ts';

should.runWhen(import.meta.url);
