import type { md } from 'node-forge';
// import util from 'node-forge/lib/util';
import { HashFunction } from './parameters';

interface CompatibleCrypto {
  hashFunctions: { [key: string]: HashFunction };
  randomBytes: (array: Uint8Array) => Uint8Array;
}

export let crossEnvCrypto: CompatibleCrypto;

try {
  const webcrypto =
    (typeof window !== 'undefined' && window.crypto) ||
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require('crypto').webcrypto; // Node v15+ has webcrypto built in, lets use that if we can

  if (webcrypto) {
    if (!webcrypto.subtle) {
      const md = import('node-forge/lib/md.all');
      const utilImport = import('node-forge/lib/util');
      const digestFunctionToHashFunction = (factory: Promise<() => md.MessageDigest>) => async (data: ArrayBuffer): Promise<ArrayBuffer> => {
        const create = await factory;
        const util = await utilImport;
        const messageDigest = create();
        messageDigest.update(util.binary.raw.encode(new Uint8Array(data)));
        return Promise.resolve(util.binary.raw.decode(messageDigest.digest().getBytes()));
      };

      crossEnvCrypto = {
        randomBytes: webcrypto.getRandomValues.bind(webcrypto),
        hashFunctions: {
          SHA1: digestFunctionToHashFunction(md.then(({ sha1 }) => sha1.create)),
          SHA256: digestFunctionToHashFunction(md.then(({ sha256 }) => sha256.create)),
          SHA384: digestFunctionToHashFunction(md.then(({ sha384 }) => sha384.create)),
          SHA512: digestFunctionToHashFunction(md.then(({ sha512 }) => sha512.create)),
        },
      };
    } else {
      const digestFunctionToHashFunction =
        (algorithm: AlgorithmIdentifier) => (data: ArrayBuffer) =>
          webcrypto.subtle.digest(algorithm, data);
      crossEnvCrypto = {
        randomBytes: webcrypto.getRandomValues.bind(webcrypto),
        hashFunctions: {
          SHA1: digestFunctionToHashFunction('SHA-1'),
          SHA256: digestFunctionToHashFunction('SHA-256'),
          SHA384: digestFunctionToHashFunction('SHA-384'),
          SHA512: digestFunctionToHashFunction('SHA-512'),
        },
      };
    }
  } else {
    // otherwise lets use node's crypto
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto');
    const nodeCreateHashToHashFunction =
      (algorithm: AlgorithmIdentifier) => (data: ArrayBuffer) =>
        nodeCrypto.createHash(algorithm).update(data).digest().buffer;

    crossEnvCrypto = {
      randomBytes: nodeCrypto.randomFillSync,
      hashFunctions: {
        SHA1: nodeCreateHashToHashFunction('sha1'),
        SHA256: nodeCreateHashToHashFunction('sha256'),
        SHA384: nodeCreateHashToHashFunction('sha384'),
        SHA512: nodeCreateHashToHashFunction('sha512'),
      },
    };
  }
} catch (e) {
  console.error(e);
  throw new Error(
    'No suitable crypto library was found. You may need a polyfill.',
  );
}
