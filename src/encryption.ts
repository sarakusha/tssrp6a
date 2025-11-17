import { bigIntToArrayBuffer, hash } from "./utils";
import { SRPParameters } from "./parameters";

/**
 * Derive encryption and MAC keys from shared session secret S
 * Returns { encKey: 32 bytes, macKey: 32 bytes }
 */
async function deriveKeys(
  S: bigint,
): Promise<{ encKey: ArrayBuffer; macKey: ArrayBuffer }> {
  const params = new SRPParameters();
  const sBytes = bigIntToArrayBuffer(S);

  // Derive encryption key: H(S || "encryption")
  const encKey = await hash(
    params,
    sBytes,
    new TextEncoder().encode("encryption").buffer,
  );

  // Derive MAC key: H(S || "authentication")
  const macKey = await hash(
    params,
    sBytes,
    new TextEncoder().encode("authentication").buffer,
  );

  return { encKey, macKey };
}

/**
 * Generate random IV (16 bytes for compatibility)
 */
function generateIV(): ArrayBuffer {
  const iv = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    iv[i] = Math.floor(Math.random() * 256);
  }
  return iv.buffer;
}

/**
 * XOR encryption/decryption (stream cipher from key material)
 */
function xorCrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const result = new Uint8Array(data.length);
  const keyStream = new Uint8Array(data.length);

  // Generate keystream by repeating (key XOR iv) pattern
  for (let i = 0; i < data.length; i++) {
    keyStream[i] = key[i % key.length] ^ iv[i % iv.length];
  }

  // XOR data with keystream
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ keyStream[i];
  }

  return result;
}

/**
 * Compute HMAC-like authentication tag using available hash
 */
async function computeMAC(
  macKey: ArrayBuffer,
  iv: ArrayBuffer,
  ciphertext: ArrayBuffer,
): Promise<ArrayBuffer> {
  const params = new SRPParameters();
  return hash(params, macKey, iv, ciphertext);
}

/**
 * Encrypt data using stream cipher with authentication
 * @param sessionKey - Shared session secret S (bigint)
 * @param data - Data to encrypt (string or ArrayBuffer)
 * @returns Object with iv and ciphertext (encrypted data + auth tag)
 */
export async function encrypt(
  sessionKey: bigint,
  data: string | ArrayBuffer,
): Promise<{ iv: ArrayBuffer; ciphertext: ArrayBuffer }> {
  const { encKey, macKey } = await deriveKeys(sessionKey);
  const iv = generateIV();

  // Convert data to bytes
  const plaintext =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : new Uint8Array(data);

  // Encrypt with XOR
  const encrypted = xorCrypt(
    plaintext,
    new Uint8Array(encKey),
    new Uint8Array(iv),
  );

  // Compute MAC over IV + ciphertext
  const encryptedBuffer = encrypted.buffer as ArrayBuffer;
  const mac = await computeMAC(macKey, iv, encryptedBuffer);

  // Combine ciphertext + MAC (first 16 bytes of hash as tag)
  const tag = new Uint8Array(mac).slice(0, 16);
  const combined = new Uint8Array(encrypted.length + tag.length);
  combined.set(encrypted, 0);
  combined.set(tag, encrypted.length);

  return {
    iv,
    ciphertext: combined.buffer,
  };
}

/**
 * Decrypt data using stream cipher with authentication
 * @param sessionKey - Shared session secret S (bigint)
 * @param iv - Initialization vector
 * @param ciphertext - Encrypted data with auth tag (ciphertext + 16 byte tag)
 * @returns Decrypted data as ArrayBuffer
 */
export async function decrypt(
  sessionKey: bigint,
  iv: ArrayBuffer,
  ciphertext: ArrayBuffer,
): Promise<ArrayBuffer> {
  const { encKey, macKey } = await deriveKeys(sessionKey);

  // Split ciphertext and tag (last 16 bytes)
  const ctBuffer = new Uint8Array(ciphertext);
  if (ctBuffer.length < 16) {
    throw new Error("Ciphertext too short (must include 16-byte auth tag)");
  }

  const actualCiphertext = ctBuffer.slice(0, ctBuffer.length - 16);
  const receivedTag = ctBuffer.slice(ctBuffer.length - 16);

  // Verify MAC
  const computedMAC = await computeMAC(macKey, iv, actualCiphertext.buffer);
  const computedTag = new Uint8Array(computedMAC).slice(0, 16);

  // Constant-time comparison
  let tagMatch = true;
  for (let i = 0; i < 16; i++) {
    if (receivedTag[i] !== computedTag[i]) {
      tagMatch = false;
    }
  }

  if (!tagMatch) {
    throw new Error("Decryption failed (authentication tag mismatch)");
  }

  // Decrypt with XOR
  const decrypted = xorCrypt(
    actualCiphertext,
    new Uint8Array(encKey),
    new Uint8Array(iv),
  );

  return decrypted.buffer as ArrayBuffer;
}

/**
 * Decrypt and return as UTF-8 string
 */
export async function decryptToString(
  sessionKey: bigint,
  iv: ArrayBuffer,
  ciphertext: ArrayBuffer,
): Promise<string> {
  const decrypted = await decrypt(sessionKey, iv, ciphertext);
  return new TextDecoder().decode(decrypted);
}
