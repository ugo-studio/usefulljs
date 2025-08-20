// --- Custom Error Handling ---

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
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = "SHA-256";
const EXPIRATION_LENGTH_BYTES = 8; // 64-bit float for the timestamp
const DEFAULT_TTL_MS: number = 60 * 60 * 1000; // 1 hour

// --- Helper Functions ---

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
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
 * Encrypts a plaintext string using AES-256-GCM, embedding a TTL.
 *
 * @param plaintext The string to encrypt.
 * @param secretKey The secret key for key derivation.
 * @param ttl The Time-To-Live in milliseconds. Pass `null` to disable expiration. Defaults to 1 hour.
 * @returns A Promise resolving to a URL-safe, Base64 encoded string containing: expiration + salt + iv + encryptedData.
 * @throws {CryptoError} If the environment is unsupported or encryption fails.
 */
export async function encryptString(
  plaintext: string,
  secretKey: string,
  options: { ttl?: number | null } = {},
): Promise<string> {
  ensureWebCryptoAvailable();

  const { ttl = DEFAULT_TTL_MS } = options;

  try {
    // 1. Calculate the expiration timestamp. Use Infinity for a null TTL.
    const expirationTimestamp = ttl === null ? Infinity : Date.now() + ttl;
    const expirationBuffer = new ArrayBuffer(EXPIRATION_LENGTH_BYTES);
    new DataView(expirationBuffer).setFloat64(0, expirationTimestamp, false); // Big-endian

    // 2. Generate cryptographic primitives.
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

    // 3. Derive the encryption key from the secret.
    const passwordKeyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secretKey),
      { name: KEY_DERIVATION_ALGORITHM },
      false,
      ["deriveKey"],
    );
    const derivedEncryptionKey = await crypto.subtle.deriveKey(
      {
        name: KEY_DERIVATION_ALGORITHM,
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      passwordKeyMaterial,
      { name: ALGORITHM_NAME, length: KEY_LENGTH_BITS },
      false,
      ["encrypt"],
    );

    // 4. Encrypt the data.
    const encodedPlaintext = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: ALGORITHM_NAME, iv },
      derivedEncryptionKey,
      encodedPlaintext,
    );

    // 5. Combine all parts into a single buffer.
    const combinedData = new Uint8Array(
      EXPIRATION_LENGTH_BYTES + salt.length + iv.length + ciphertext.byteLength,
    );
    combinedData.set(new Uint8Array(expirationBuffer), 0);
    combinedData.set(salt, EXPIRATION_LENGTH_BYTES);
    combinedData.set(iv, EXPIRATION_LENGTH_BYTES + salt.length);
    combinedData.set(
      new Uint8Array(ciphertext),
      EXPIRATION_LENGTH_BYTES + salt.length + iv.length,
    );

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
 *
 * @param encryptedDataB64 The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string.
 * @throws {CryptoError} With codes:
 *   - `EXPIRED`: The data's TTL has passed.
 *   - `INVALID_DATA`: The encrypted payload is malformed or too short.
 *   - `DECRYPTION_FAILED`: The secret key is likely incorrect or the data was tampered with.
 *   - `UNSUPPORTED_ENVIRONMENT`: Web Crypto API is not available.
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

  const minLength = EXPIRATION_LENGTH_BYTES + SALT_LENGTH_BYTES +
    IV_LENGTH_BYTES;
  if (combinedData.length < minLength) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: payload is too short.",
    );
  }

  // 1. Extract expiration and enforce TTL.
  const expirationView = new DataView(
    combinedData.buffer,
    0,
    EXPIRATION_LENGTH_BYTES,
  );
  const expirationTimestamp = expirationView.getFloat64(0, false);

  if (Date.now() > expirationTimestamp) {
    throw new CryptoError("EXPIRED", "The encrypted data has expired.");
  }

  // 2. Extract salt, IV, and ciphertext.
  const saltOffset = EXPIRATION_LENGTH_BYTES;
  const ivOffset = saltOffset + SALT_LENGTH_BYTES;
  const ciphertextOffset = ivOffset + IV_LENGTH_BYTES;

  const salt = combinedData.subarray(saltOffset, ivOffset) as BufferSource;
  const iv = combinedData.subarray(ivOffset, ciphertextOffset) as BufferSource;
  const ciphertext = combinedData.subarray(ciphertextOffset) as BufferSource;

  // 3. Derive the decryption key.
  const passwordKeyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secretKey),
    { name: KEY_DERIVATION_ALGORITHM },
    false,
    ["deriveKey"],
  );
  const derivedDecryptionKey = await crypto.subtle.deriveKey(
    {
      name: KEY_DERIVATION_ALGORITHM,
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    passwordKeyMaterial,
    { name: ALGORITHM_NAME, length: KEY_LENGTH_BITS },
    false,
    ["decrypt"],
  );

  try {
    // 4. Decrypt the ciphertext.
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
 * Recursively sorts an object's keys.
 *
 * @param obj The object to sort.
 * @returns A new object with sorted keys.
 */
const sortObject = (obj: any): any => {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sortObject);
  }

  const sortedKeys = Object.keys(obj).sort();
  const sortedObj: { [key: string]: any } = {};

  for (const key of sortedKeys) {
    sortedObj[key] = sortObject(obj[key]);
  }

  return sortedObj;
};

/**
 * Asynchronously calculates the SHA-256 hash of a JavaScript object.
 *
 * This function first performs a deep sort on the object's keys to ensure that
 * the hash is deterministic, meaning that the same object will always produce
 * the same hash regardless of the original key order. After sorting, the object
 * is stringified and then hashed using the SHA-256 algorithm.
 *
 * @param obj The object to hash. This can be any serializable JavaScript object.
 * @returns A promise that resolves to a string containing the hexadecimal representation of the SHA-256 hash.
 */
export async function hashObject(obj: any): Promise<string> {
  const sortedObj = typeof obj === "object" ? sortObject(obj) : obj;
  const objectString = JSON.stringify(sortedObj);

  // Use the Web Crypto API in browsers
  const encoder = new TextEncoder();
  const data = encoder.encode(objectString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}
