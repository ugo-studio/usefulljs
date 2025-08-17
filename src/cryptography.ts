const ALGORITHM_NAME = "AES-GCM";
const KEY_DERIVATION_ALGORITHM = "PBKDF2";
const KEY_LENGTH_BITS = 256;
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = "SHA-256";

// --- New constants for TTL ---
const EXPIRATION_LENGTH_BYTES = 8; // 64-bit float for the timestamp
const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour in milliseconds

/**
 * Converts an ArrayBuffer to a Base64 encoded string.
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 encoded string to an ArrayBuffer.
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

/**
 * Checks for Web Crypto API availability.
 */
function ensureWebCryptoAvailable(): void {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(
      "Web Crypto API (crypto.subtle) is not available in this environment.",
    );
  }
}

/**
 * Encrypts a plaintext string using AES-256-GCM, embedding a TTL.
 *
 * @param plaintext The string to encrypt.
 * @param secretKey The secret key for key derivation.
 * @param ttl The Time-To-Live in milliseconds. Defaults to 1 hour.
 * @returns A Promise resolving to a Base64 encoded string containing: expiration + salt + iv + encryptedData.
 */
export const encryptString = async (
  plaintext: string,
  secretKey: string,
  ttl: number = DEFAULT_TTL_MS,
): Promise<string> => {
  ensureWebCryptoAvailable();

  try {
    // 1. Calculate the expiration timestamp.
    const expirationTimestamp = Date.now() + ttl;
    const expirationBuffer = new ArrayBuffer(EXPIRATION_LENGTH_BYTES);
    // Use DataView to handle writing a number into a buffer correctly.
    new DataView(expirationBuffer).setFloat64(0, expirationTimestamp, false); // false for big-endian
    const expirationBytes = new Uint8Array(expirationBuffer);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
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
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      passwordKeyMaterial,
      { name: ALGORITHM_NAME, length: KEY_LENGTH_BITS },
      false,
      ["encrypt"],
    );

    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
    const encodedPlaintext = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: ALGORITHM_NAME, iv: iv },
      derivedEncryptionKey,
      encodedPlaintext,
    );

    // 5. Combine expiration, salt, iv, and ciphertext into a single Uint8Array.
    // Format: expiration (8 bytes) + salt (16 bytes) + iv (12 bytes) + ciphertext
    const combinedData = new Uint8Array(
      expirationBytes.length + salt.length + iv.length + ciphertext.byteLength,
    );
    combinedData.set(expirationBytes, 0);
    combinedData.set(salt, expirationBytes.length);
    combinedData.set(iv, expirationBytes.length + salt.length);
    combinedData.set(
      new Uint8Array(ciphertext),
      expirationBytes.length + salt.length + iv.length,
    );

    return encodeURIComponent(
      arrayBufferToBase64(combinedData.buffer as ArrayBuffer),
    );
  } catch (error: any) {
    const message = `Encryption failed. ${error.message}`;
    error.message = message;
    throw error;
  }
};

/**
 * Decrypts a Base64 encoded string that was encrypted with encryptString, checking its TTL.
 *
 * @param encryptedDataB64 The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string if decryption is successful and the data is not expired.
 *          Throws an error if decryption fails or the TTL has passed.
 */
export async function decryptString(
  encryptedDataB64: string,
  secretKey: string,
): Promise<string> {
  ensureWebCryptoAvailable();

  const combinedDataBuffer = base64ToArrayBuffer(
    decodeURIComponent(encryptedDataB64),
  );
  const combinedData = new Uint8Array(combinedDataBuffer);

  // 1. Check data length and extract the expiration timestamp first.
  const minLength = EXPIRATION_LENGTH_BYTES + SALT_LENGTH_BYTES +
    IV_LENGTH_BYTES;
  if (combinedData.length < minLength) {
    throw new Error(
      "Invalid encrypted data: too short to contain expiration, salt, and IV.",
    );
  }

  const expirationView = new DataView(
    combinedData.buffer,
    0,
    EXPIRATION_LENGTH_BYTES,
  );
  const expirationTimestamp = expirationView.getFloat64(0, false); // big-endian

  // 2. Enforce the TTL.
  if (Date.now() > expirationTimestamp) {
    throw new Error("The encrypted data has expired.");
  }

  // 3. Extract salt, IV, and ciphertext using new offsets.
  const saltOffset = EXPIRATION_LENGTH_BYTES;
  const ivOffset = saltOffset + SALT_LENGTH_BYTES;
  const ciphertextOffset = ivOffset + IV_LENGTH_BYTES;

  const salt = combinedData.subarray(saltOffset, ivOffset);
  const iv = combinedData.subarray(ivOffset, ciphertextOffset);
  const ciphertext = combinedData.subarray(ciphertextOffset);

  // 4. Derive the decryption key using the extracted salt and the secret.
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
    // 5. Decrypt the ciphertext.
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: ALGORITHM_NAME, iv: iv },
      derivedDecryptionKey,
      ciphertext,
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (error: any) {
    let message = "Decryption failed.";
    if (error instanceof DOMException && error.name === "OperationError") {
      message +=
        " This often indicates a wrong secret key or that the data has been tampered with.";
    }
    error.message = message;
    throw error;
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
export async function hashObject(obj: string | object): Promise<string> {
  const sortedObj = typeof obj === "string" ? obj : sortObject(obj);
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
