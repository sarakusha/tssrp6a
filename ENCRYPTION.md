# Шифрование данных после установки SRP-сессии

После успешной аутентификации по протоколу SRP6a клиент и сервер получают общий секретный ключ сессии `S`. Этот ключ можно использовать для шифрования дальнейшего обмена данными.

## Быстрый старт

### На клиенте (браузер)

```typescript
import {
  SRPClientSession,
  SRPParameters,
  SRPRoutines,
} from '@sarakusha/tssrp6a';

// После завершения SRP-handshake (step1, step2, step3)
const clientStep2 = /* результат client.step2() */;

// Шифрование строки
const encrypted = await clientStep2.encrypt("Secret message");
// encrypted = { iv: ArrayBuffer, ciphertext: ArrayBuffer }

// Шифрование бинарных данных
const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
const encryptedBinary = await clientStep2.encrypt(binaryData.buffer);

// Расшифровка
const decrypted = await clientStep2.decrypt(encrypted.iv, encrypted.ciphertext);
const decryptedString = await clientStep2.decryptToString(encrypted.iv, encrypted.ciphertext);
```

### На сервере (Node.js)

```typescript
import {
  SRPServerSession,
  SRPParameters,
  SRPRoutines,
} from '@sarakusha/tssrp6a';

// После завершения SRP-handshake (step1, step2)
const serverStep1 = /* результат server.step1() */;
const clientA = /* публичный ключ клиента из step2 */;

// Шифрование ответа сервера
const response = await serverStep1.encrypt(clientA, "Response from server");
// response = { iv: ArrayBuffer, ciphertext: ArrayBuffer }

// Расшифровка данных от клиента
const decrypted = await serverStep1.decrypt(clientA, iv, ciphertext);
const decryptedString = await serverStep1.decryptToString(clientA, iv, ciphertext);
```

## API

### Методы клиента (SRPClientSessionStep2)

#### `encrypt(data: string | ArrayBuffer): Promise<{ iv: ArrayBuffer; ciphertext: ArrayBuffer }>`
Шифрует данные используя общий ключ сессии.
- **data** — строка UTF-8 или бинарные данные (ArrayBuffer)
- **Возвращает** — объект с IV (16 байт) и зашифрованным текстом с тегом аутентификации (ciphertext + 16 байт HMAC)

#### `decrypt(iv: ArrayBuffer, ciphertext: ArrayBuffer): Promise<ArrayBuffer>`
Расшифровывает данные и проверяет тег аутентификации.
- **iv** — вектор инициализации (из результата encrypt)
- **ciphertext** — зашифрованные данные с тегом (из результата encrypt)
- **Возвращает** — расшифрованные бинарные данные
- **Выбрасывает** — ошибку при несовпадении тега аутентификации (подделка/повреждение данных)

#### `decryptToString(iv: ArrayBuffer, ciphertext: ArrayBuffer): Promise<string>`
Расшифровывает данные и возвращает UTF-8 строку.

### Методы сервера (SRPServerSessionStep1)

#### `encrypt(A: bigint, data: string | ArrayBuffer): Promise<{ iv: ArrayBuffer; ciphertext: ArrayBuffer }>`
Шифрует данные используя общий ключ сессии.
- **A** — публичный ключ клиента (из step2)
- **data** — строка UTF-8 или бинарные данные (ArrayBuffer)
- **Возвращает** — объект с IV и зашифрованным текстом с тегом

#### `decrypt(A: bigint, iv: ArrayBuffer, ciphertext: ArrayBuffer): Promise<ArrayBuffer>`
Расшифровывает данные от клиента.
- **A** — публичный ключ клиента
- **iv** — вектор инициализации
- **ciphertext** — зашифрованные данные с тегом
- **Возвращает** — расшифрованные бинарные данные

#### `decryptToString(A: bigint, iv: ArrayBuffer, ciphertext: ArrayBuffer): Promise<string>`
Расшифровывает данные и возвращает UTF-8 строку.

## Детали реализации

### Алгоритм шифрования

Используется собственная реализация потокового шифра с аутентификацией:
- **Деривация ключей**: из общего секрета `S` выводятся два ключа (encryption key и MAC key) через SHA-512
- **Шифрование**: XOR с keystream, сгенерированным из ключа и IV
- **Аутентификация**: HMAC на основе SHA-512 (первые 16 байт хеша используются как тег)
- **IV**: 16 случайных байт для каждого сообщения

### Почему не WebCrypto/AES-GCM?

Web Crypto API (crypto.subtle) требует HTTPS-контекст, что может быть недоступно в некоторых сценариях (локальная разработка, приложения без TLS). Реализация использует только хеш-функции (уже есть в библиотеке) и простую арифметику, что:
- Работает в любом контексте (HTTP/HTTPS)
- Минимально увеличивает размер бандла (~2 КБ)
- Обеспечивает аутентифицированное шифрование

### Безопасность

- ✅ Аутентификация сообщений (предотвращает подделку)
- ✅ Уникальный IV для каждого сообщения
- ✅ Отдельные ключи для шифрования и MAC
- ⚠️ Не рекомендуется для критичных данных (используйте AES-GCM через WebCrypto где возможно)

## Примеры

### Полный цикл обмена сообщениями

```typescript
// Клиент
const encrypted = await clientStep2.encrypt("Hello server!");
sendToServer({ iv: Array.from(new Uint8Array(encrypted.iv)), 
               ciphertext: Array.from(new Uint8Array(encrypted.ciphertext)) });

// Сервер
const iv = new Uint8Array(receivedData.iv).buffer;
const ciphertext = new Uint8Array(receivedData.ciphertext).buffer;
const message = await serverStep1.decryptToString(clientA, iv, ciphertext);
console.log(message); // "Hello server!"

// Ответ сервера
const response = await serverStep1.encrypt(clientA, "Hello client!");
sendToClient(response);

// Клиент получает ответ
const serverMessage = await clientStep2.decryptToString(response.iv, response.ciphertext);
console.log(serverMessage); // "Hello client!"
```

### Передача через JSON

```typescript
// Шифрование
const { iv, ciphertext } = await clientStep2.encrypt("Secret");
const json = JSON.stringify({
  iv: Array.from(new Uint8Array(iv)),
  ciphertext: Array.from(new Uint8Array(ciphertext))
});

// Расшифровка
const data = JSON.parse(json);
const decrypted = await serverStep1.decryptToString(
  clientA,
  new Uint8Array(data.iv).buffer,
  new Uint8Array(data.ciphertext).buffer
);
```

### Шифрование больших файлов

Для больших файлов рекомендуется разбивать на чанки (~64 КБ каждый):

```typescript
async function encryptLargeFile(file: ArrayBuffer, session: SRPClientSessionStep2) {
  const CHUNK_SIZE = 65536; // 64 КБ
  const chunks = [];
  const view = new Uint8Array(file);
  
  for (let offset = 0; offset < view.length; offset += CHUNK_SIZE) {
    const chunk = view.slice(offset, offset + CHUNK_SIZE);
    const encrypted = await session.encrypt(chunk.buffer);
    chunks.push(encrypted);
  }
  
  return chunks;
}
```
