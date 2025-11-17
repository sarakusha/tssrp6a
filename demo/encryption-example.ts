/**
 * Пример использования шифрования после SRP-аутентификации
 * 
 * Запуск:
 *   pnpm build
 *   node -r ts-node/register demo/encryption-example.ts
 * 
 * Этот пример показывает полный цикл:
 * 1. SRP handshake (аутентификация)
 * 2. Шифрование сообщения на клиенте
 * 3. Расшифровка на сервере
 * 4. Ответ сервера (зашифрованный)
 * 5. Расшифровка ответа на клиенте
 * 6. Детекция подделки данных
 */

import {
  SRPParameters,
  SRPRoutines,
  SRPClientSession,
  SRPServerSession,
  createVerifierAndSalt,
} from '../src/index.js';

async function main() {
  console.log('=== SRP6a Authentication with Encryption Example ===\n');

  const username = 'alice';
  const password = 'secret123';

  // 1. Setup: генерация verifier и salt (обычно делается при регистрации)
  const routines = new SRPRoutines(new SRPParameters());
  const { s: salt, v: verifier } = await createVerifierAndSalt(
    routines,
    username,
    password,
  );
  console.log('✓ Generated verifier and salt');

  // 2. SRP Handshake
  console.log('\n--- SRP Handshake ---');

  // Client step 1
  const clientSession = new SRPClientSession(routines);
  const clientStep1 = await clientSession.step1(username, password);
  console.log('Client: step1 complete');

  // Server step 1
  const serverSession = new SRPServerSession(routines);
  const serverStep1 = await serverSession.step1(username, salt, verifier);
  console.log('Server: step1 complete, B =', serverStep1.B.toString(16).slice(0, 20) + '...');

  // Client step 2
  const clientStep2 = await clientStep1.step2(salt, serverStep1.B);
  console.log('Client: step2 complete, A =', clientStep2.A.toString(16).slice(0, 20) + '...');

  // Server step 2 (verification)
  const M2 = await serverStep1.step2(clientStep2.A, clientStep2.M1);
  console.log('Server: verified client, M2 generated');

  // Client step 3 (verification)
  await clientStep2.step3(M2);
  console.log('Client: verified server');
  console.log('✓ Mutual authentication complete!\n');

  // 3. Теперь можно безопасно обмениваться сообщениями
  console.log('--- Encrypted Communication ---');

  // Client → Server
  const clientMessage = 'Hello, secure server!';
  console.log('\nClient sends:', JSON.stringify(clientMessage));

  const encrypted = await clientStep2.encrypt(clientMessage);
  console.log('  Encrypted (IV):', Buffer.from(encrypted.iv).toString('hex').slice(0, 32) + '...');
  console.log('  Encrypted (CT):', Buffer.from(encrypted.ciphertext).toString('hex').slice(0, 32) + '...');

  // Server расшифровывает
  const decryptedOnServer = await serverStep1.decryptToString(
    clientStep2.A,
    encrypted.iv,
    encrypted.ciphertext,
  );
  console.log('Server received:', JSON.stringify(decryptedOnServer));
  console.log('✓ Message delivered securely');

  // Server → Client
  const serverResponse = 'Authentication successful. Welcome!';
  console.log('\nServer sends:', JSON.stringify(serverResponse));

  const encryptedResponse = await serverStep1.encrypt(
    clientStep2.A,
    serverResponse,
  );
  console.log('  Encrypted (IV):', Buffer.from(encryptedResponse.iv).toString('hex').slice(0, 32) + '...');
  console.log('  Encrypted (CT):', Buffer.from(encryptedResponse.ciphertext).toString('hex').slice(0, 32) + '...');

  // Client расшифровывает
  const decryptedOnClient = await clientStep2.decryptToString(
    encryptedResponse.iv,
    encryptedResponse.ciphertext,
  );
  console.log('Client received:', JSON.stringify(decryptedOnClient));
  console.log('✓ Response delivered securely');

  // 4. Попытка подделки данных (должна провалиться)
  console.log('\n--- Tampering Detection ---');
  const tampered = new Uint8Array(encrypted.ciphertext);
  tampered[0] ^= 0xff; // изменяем один байт

  try {
    await serverStep1.decrypt(clientStep2.A, encrypted.iv, tampered.buffer);
    console.log('✗ Tampering NOT detected (this is bad!)');
  } catch (error) {
    console.log('✓ Tampering detected:', (error as Error).message);
  }

  console.log('\n=== Example Complete ===');
}

main().catch(console.error);
