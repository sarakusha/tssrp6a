import type { md } from 'node-forge';
// import util from 'node-forge/lib/util';
import type { HashFunction } from './parameters';

interface CompatibleCrypto {
  hashFunctions: { [key: string]: HashFunction };
  randomBytes: (array: Uint8Array) => Uint8Array;
}

export let crossEnvCrypto: CompatibleCrypto;

async function getCrypto(): Promise<Crypto> {
  if (typeof globalThis.crypto !== "undefined") {
    return globalThis.crypto as Crypto;
  } else {
    const { webcrypto } = await import("node:crypto");
    return webcrypto as Crypto;
  }
}

export async function getCompatibleCrypto(): Promise<CompatibleCrypto> {
  if (!crossEnvCrypto) {
    const webcrypto = await getCrypto();

    if (!webcrypto.subtle) {
      console.log(
        "Using node-forge for hashing since Web Crypto Subtle is not available.",
      );
      // const { util, md } = await import('node-forge');
      const md = await import('node-forge/lib/md.all');
      const util = await import('node-forge/lib/util');
      const digestFunctionToHashFunction = (create: () => md.MessageDigest) => async (data: ArrayBuffer): Promise<ArrayBuffer> => {
        const messageDigest = create();
        messageDigest.update(util.binary.raw.encode(new Uint8Array(data)));
        return util.binary.raw.decode(messageDigest.digest().getBytes()).buffer as ArrayBuffer;
      };

      crossEnvCrypto = {
        randomBytes: webcrypto.getRandomValues.bind(webcrypto),
        hashFunctions: {
          SHA1: digestFunctionToHashFunction(md.sha1.create),
          SHA256: digestFunctionToHashFunction(md.sha256.create),
          SHA384: digestFunctionToHashFunction(md.sha384.create),
          SHA512: digestFunctionToHashFunction(md.sha512.create),
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
  }
  return crossEnvCrypto;
}