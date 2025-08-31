// --- Custom Error Handling ---

import { createCanonicalString } from "../utils";

/**
 * A set of specific error codes for cryptographic operations.
 */
export type CryptoErrorCode =
  | "UNSUPPORTED_ENVIRONMENT"
  | "ENCRYPTION_FAILED"
  | "DECRYPTION_FAILED"
  | "INVALID_DATA"
  | "EXPIRED";

/**
 * Custom error class for handling specific cryptographic failures.
 * This allows for robust error handling using `instanceof` or by checking the `code`.
 */
export class CryptoError extends Error {
  public readonly code: CryptoErrorCode;
  public readonly cause?: Error;

  constructor(code: CryptoErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
    this.cause = cause;
  }
}

// --- Cryptographic Constants ---
const ALGORITHM_NAME = "AES-GCM";
const KEY_DERIVATION_ALGORITHM = "PBKDF2";
const KEY_LENGTH_BITS = 256;
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;
const PBKDF2_HASH = "SHA-256";
const EXPIRATION_LENGTH_BYTES = 8; // 64-bit float for the timestamp
const ITERATIONS_LENGTH_BYTES = 4; // 32-bit unsigned integer for iterations

// --- Default Configuration ---
const DEFAULT_TTL_MS: number = 60 * 60 * 1000; // 1 hour
const DEFAULT_PBKDF2_ITERATIONS = 100000;

// --- Helper Functions ---

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 8192; // Process in 8KB chunks
  let result = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    // String.fromCharCode.apply is more performant than a spread operator for this use case.
    result += String.fromCharCode.apply(null, chunk as any);
  }

  return btoa(result);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function ensureWebCryptoAvailable(): void {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new CryptoError(
      "UNSUPPORTED_ENVIRONMENT",
      "Web Crypto API (crypto.subtle) is not available in this environment.",
    );
  }
}

/**
 * Derives a cryptographic key from a secret string using PBKDF2.
 * @internal
 */
async function _deriveKey(
  secretKey: string,
  salt: BufferSource,
  iterations: number,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  const passwordKeyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secretKey),
    { name: KEY_DERIVATION_ALGORITHM },
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: KEY_DERIVATION_ALGORITHM,
      salt,
      iterations,
      hash: PBKDF2_HASH,
    },
    passwordKeyMaterial,
    { name: ALGORITHM_NAME, length: KEY_LENGTH_BITS },
    false,
    usage,
  );
}

/**
 * Encrypts a plaintext string using AES-256-GCM, embedding TTL and iteration count.
 *
 * @param plaintext The string to encrypt.
 * @param secretKey The secret key for key derivation.
 * @param options Configuration for TTL and PBKDF2 iterations.
 * @param options.ttl The Time-To-Live in milliseconds. Pass `null` for no expiration. Defaults to 1 hour.
 * @param options.pbkdf2Iterations The number of iterations for key derivation.
 *        **WARNING**: Reducing this from the default weakens security.
 * @returns A Promise resolving to a URL-safe, Base64 encoded string.
 * @throws {CryptoError} If the environment is unsupported or encryption fails.
 */
export async function encryptString(
  plaintext: string,
  secretKey: string,
  options: { ttl?: number | null; pbkdf2Iterations?: number } = {},
): Promise<string> {
  ensureWebCryptoAvailable();

  const {
    ttl = DEFAULT_TTL_MS,
    pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS,
  } = options;

  try {
    // 1. Store the iteration count and expiration timestamp.
    const iterationsBuffer = new ArrayBuffer(ITERATIONS_LENGTH_BYTES);
    new DataView(iterationsBuffer).setUint32(0, pbkdf2Iterations, false); // Big-endian

    const expirationTimestamp = ttl === null ? Infinity : Date.now() + ttl;
    const expirationBuffer = new ArrayBuffer(EXPIRATION_LENGTH_BYTES);
    new DataView(expirationBuffer).setFloat64(0, expirationTimestamp, false);

    // 2. Generate salt and IV.
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

    // 3. Derive the encryption key.
    const derivedEncryptionKey = await _deriveKey(
      secretKey,
      salt,
      pbkdf2Iterations,
      ["encrypt"],
    );

    // 4. Encrypt the data.
    const encodedPlaintext = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: ALGORITHM_NAME, iv },
      derivedEncryptionKey,
      encodedPlaintext,
    );

    // 5. Combine [iterations, expiration, salt, iv, ciphertext] into a single buffer.
    const combinedData = new Uint8Array(
      ITERATIONS_LENGTH_BYTES +
        EXPIRATION_LENGTH_BYTES +
        salt.length +
        iv.length +
        ciphertext.byteLength,
    );
    let offset = 0;
    combinedData.set(new Uint8Array(iterationsBuffer), offset);
    offset += ITERATIONS_LENGTH_BYTES;
    combinedData.set(new Uint8Array(expirationBuffer), offset);
    offset += EXPIRATION_LENGTH_BYTES;
    combinedData.set(salt, offset);
    offset += salt.length;
    combinedData.set(iv, offset);
    offset += iv.length;
    combinedData.set(new Uint8Array(ciphertext), offset);

    return encodeURIComponent(arrayBufferToBase64(combinedData.buffer));
  } catch (error: any) {
    throw new CryptoError(
      "ENCRYPTION_FAILED",
      `Encryption failed: ${error.message}`,
      error,
    );
  }
}

/**
 * Decrypts a string that was encrypted with encryptString, checking its TTL.
 * The iteration count is automatically extracted from the payload.
 *
 * @param encryptedDataB64 The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string.
 * @throws {CryptoError}
 */
export async function decryptString(
  encryptedDataB64: string,
  secretKey: string,
): Promise<string> {
  ensureWebCryptoAvailable();

  let combinedData: Uint8Array;
  try {
    const combinedDataBuffer = base64ToArrayBuffer(
      decodeURIComponent(encryptedDataB64),
    );
    combinedData = new Uint8Array(combinedDataBuffer);
  } catch (error: any) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: failed to decode base64 payload.",
      error,
    );
  }

  const minLength = ITERATIONS_LENGTH_BYTES +
    EXPIRATION_LENGTH_BYTES +
    SALT_LENGTH_BYTES +
    IV_LENGTH_BYTES;
  if (combinedData.length < minLength) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: payload is too short.",
    );
  }

  // 1. Extract iterations and expiration.
  let offset = 0;
  const iterationsView = new DataView(
    combinedData.buffer,
    offset,
    ITERATIONS_LENGTH_BYTES,
  );
  const pbkdf2Iterations = iterationsView.getUint32(0, false);
  offset += ITERATIONS_LENGTH_BYTES;

  const expirationView = new DataView(
    combinedData.buffer,
    offset,
    EXPIRATION_LENGTH_BYTES,
  );
  const expirationTimestamp = expirationView.getFloat64(0, false);
  offset += EXPIRATION_LENGTH_BYTES;

  // 2. Check for expiration.
  if (Date.now() > expirationTimestamp) {
    throw new CryptoError("EXPIRED", "The encrypted data has expired.");
  }

  // 3. Extract salt, IV, and ciphertext.
  const salt = combinedData.subarray(
    offset,
    offset + SALT_LENGTH_BYTES,
  ) as BufferSource;
  offset += SALT_LENGTH_BYTES;
  const iv = combinedData.subarray(
    offset,
    offset + IV_LENGTH_BYTES,
  ) as BufferSource;
  offset += IV_LENGTH_BYTES;
  const ciphertext = combinedData.subarray(offset) as BufferSource;

  // 4. Derive the decryption key using the extracted iteration count.
  const derivedDecryptionKey = await _deriveKey(
    secretKey,
    salt,
    pbkdf2Iterations,
    ["decrypt"],
  );

  try {
    // 5. Decrypt the ciphertext.
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: ALGORITHM_NAME, iv: iv },
      derivedDecryptionKey,
      ciphertext,
    );
    return new TextDecoder().decode(decryptedBuffer);
  } catch (error: any) {
    throw new CryptoError(
      "DECRYPTION_FAILED",
      "Decryption failed. This is often caused by a wrong secret key or tampered data.",
      error,
    );
  }
}

/**
 * Asynchronously calculates a deterministic SHA-256 hash of any JavaScript object.
 *
 * This function handles complex data structures including Maps, Sets, Dates,
 * BigInts, and circular references. It creates a consistent, sorted string
 * representation of the object, ensuring that the same logical object always
 * produces the same hash, regardless of key order or environment.
 *
 * @param obj The object to hash. This can be any serializable JavaScript value.
 * @returns A promise that resolves to a string containing the hexadecimal representation of the SHA-256 hash.
 * @example
 * const obj1 = { b: 2, a: { c: 3, d: new Set([1, 2]) } };
 * const obj2 = { a: { d: new Set([2, 1]), c: 3 }, b: 2 };
 * const hash1 = await hashObject(obj1);
 * const hash2 = await hashObject(obj2);
 * // hash1 will be identical to hash2
 */
export async function hashObject(obj: any): Promise<string> {
  const objectString = createCanonicalString(obj);

  // Use the Web Crypto API, which is available in modern browsers and Node.js (v15.7+)
  const encoder = new TextEncoder();
  const data = encoder.encode(objectString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}
