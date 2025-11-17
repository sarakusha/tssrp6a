import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { SRPServerSession } from "../src/session-server";
import { createVerifierAndSalt, generateRandomString } from "../src/utils";
import { test } from "./tests";

test("#Encryption - client encrypts, server decrypts", async (t) => {
  t.plan(3);

  const testUsername = await generateRandomString(10);
  const testPassword = await generateRandomString(15);
  const testMessage = "Hello, secure world!";

  const routines = new SRPRoutines(new SRPParameters());

  // Setup: create verifier and salt
  const { s: salt, v: verifier } = await createVerifierAndSalt(
    routines,
    testUsername,
    testPassword,
  );

  // Client step 1
  const clientStep1 = await new SRPClientSession(routines).step1(
    testUsername,
    testPassword,
  );

  // Server step 1
  const serverStep1 = await new SRPServerSession(routines).step1(
    testUsername,
    salt,
    verifier,
  );

  // Client step 2
  const clientStep2 = await clientStep1.step2(salt, serverStep1.B);

  // Server step 2 (verify client)
  const M2 = await serverStep1.step2(clientStep2.A, clientStep2.M1);

  // Client step 3 (verify server)
  await clientStep2.step3(M2);

  // Now both have established secure session
  // Client encrypts
  const { iv, ciphertext } = await clientStep2.encrypt(testMessage);
  t.ok(iv.byteLength === 16, "IV should be 16 bytes");
  t.ok(ciphertext.byteLength > 0, "Ciphertext should not be empty");

  // Server decrypts
  const decrypted = await serverStep1.decryptToString(
    clientStep2.A,
    iv,
    ciphertext,
  );
  t.equals(decrypted, testMessage, "Decrypted message matches original");
});

test("#Encryption - server encrypts, client decrypts", async (t) => {
  t.plan(2);

  const testUsername = await generateRandomString(10);
  const testPassword = await generateRandomString(15);
  const serverMessage = "Response from server";

  const routines = new SRPRoutines(new SRPParameters());

  // Setup
  const { s: salt, v: verifier } = await createVerifierAndSalt(
    routines,
    testUsername,
    testPassword,
  );

  // Handshake
  const clientStep1 = await new SRPClientSession(routines).step1(
    testUsername,
    testPassword,
  );
  const serverStep1 = await new SRPServerSession(routines).step1(
    testUsername,
    salt,
    verifier,
  );
  const clientStep2 = await clientStep1.step2(salt, serverStep1.B);
  const M2 = await serverStep1.step2(clientStep2.A, clientStep2.M1);
  await clientStep2.step3(M2);

  // Server encrypts
  const { iv, ciphertext } = await serverStep1.encrypt(
    clientStep2.A,
    serverMessage,
  );
  t.ok(ciphertext.byteLength > 0, "Ciphertext should not be empty");

  // Client decrypts
  const decrypted = await clientStep2.decryptToString(iv, ciphertext);
  t.equals(decrypted, serverMessage, "Decrypted message matches original");
});

test("#Encryption - binary data (ArrayBuffer)", async (t) => {
  t.plan(2);

  const testUsername = await generateRandomString(10);
  const testPassword = await generateRandomString(15);
  const binaryData = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 0]);

  const routines = new SRPRoutines(new SRPParameters());

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    routines,
    testUsername,
    testPassword,
  );

  const clientStep1 = await new SRPClientSession(routines).step1(
    testUsername,
    testPassword,
  );
  const serverStep1 = await new SRPServerSession(routines).step1(
    testUsername,
    salt,
    verifier,
  );
  const clientStep2 = await clientStep1.step2(salt, serverStep1.B);
  const M2 = await serverStep1.step2(clientStep2.A, clientStep2.M1);
  await clientStep2.step3(M2);

  // Encrypt binary data
  const { iv, ciphertext } = await clientStep2.encrypt(binaryData.buffer);
  t.ok(ciphertext.byteLength > 0, "Ciphertext should not be empty");

  // Decrypt
  const decrypted = await serverStep1.decrypt(
    clientStep2.A,
    iv,
    ciphertext,
  );
  const decryptedArray = new Uint8Array(decrypted);
  t.deepEqual(
    Array.from(decryptedArray),
    Array.from(binaryData),
    "Decrypted binary data matches original",
  );
});

test("#Encryption - tampered ciphertext fails", async (t) => {
  t.plan(1);

  const testUsername = await generateRandomString(10);
  const testPassword = await generateRandomString(15);
  const testMessage = "Secret message";

  const routines = new SRPRoutines(new SRPParameters());

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    routines,
    testUsername,
    testPassword,
  );

  const clientStep1 = await new SRPClientSession(routines).step1(
    testUsername,
    testPassword,
  );
  const serverStep1 = await new SRPServerSession(routines).step1(
    testUsername,
    salt,
    verifier,
  );
  const clientStep2 = await clientStep1.step2(salt, serverStep1.B);
  const M2 = await serverStep1.step2(clientStep2.A, clientStep2.M1);
  await clientStep2.step3(M2);

  const { iv, ciphertext } = await clientStep2.encrypt(testMessage);

  // Tamper with ciphertext
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  // Should fail authentication
  await t.rejects(
    () => serverStep1.decrypt(clientStep2.A, iv, tampered.buffer),
    /authentication tag mismatch/i,
    "Tampered ciphertext should fail authentication",
  );
});
