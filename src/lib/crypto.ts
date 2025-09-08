import { createCanonicalString } from "../utils.js";

// --- Custom Error Handling ---
export type CryptoErrorCode =
  | "UNSUPPORTED_ENVIRONMENT"
  | "ENCRYPTION_FAILED"
  | "DECRYPTION_FAILED"
  | "INVALID_DATA"
  | "INVALID_KEY"
  | "EXPIRED";

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

// --- Constants/Defaults ---
const DEFAULT_TTL_MS = 60 * 60 * 1000;
const DEFAULT_PBKDF2_ITERATIONS = 100_000;

const DEFAULT_ALGO = "AES-GCM" as const;
const DEFAULT_KEY_LEN: 128 | 256 = 256;
const DEFAULT_SALT_LEN = 16;
const DEFAULT_IV_LEN = 12;

type CipherAlgorithm = "AES-GCM";
type KdfAlgorithm = "PBKDF2" | "HKDF" | "NONE";
type HashAlg = "SHA-256" | "SHA-384" | "SHA-512";

// Header: [0x45,0x47,'E','G']? keep small: 2B magic + 1B version + 1B flags + 1B saltLen + 1B ivLen + 4B iters + 8B exp
const HEADER_MAGIC0 = 0x45; // 'E'
const HEADER_MAGIC1 = 0x47; // 'G'
const HEADER_VERSION = 1;
const HEADER_SIZE = 18;

enum KdfId {
  PBKDF2 = 0,
  HKDF = 1,
  NONE = 2,
}
enum HashId {
  SHA256 = 0,
  SHA384 = 1,
  SHA512 = 2,
}
enum AlgoId {
  AES_GCM = 0,
}

// flags layout (1 byte):
// bits 0-1: KDF (0 PBKDF2, 1 HKDF, 2 NONE)
// bit  2  : keyLen (0 => 128, 1 => 256)
// bits 3-4: hash (0 256, 1 384, 2 512)
// bit  5  : algo (0 AES-GCM)
// bits 6-7: reserved
function packFlags(
  kdf: KdfAlgorithm,
  keyLen: 128 | 256,
  hash: HashAlg,
  algo: CipherAlgorithm,
): number {
  const kdfBits = kdf === "PBKDF2"
    ? KdfId.PBKDF2
    : kdf === "HKDF"
    ? KdfId.HKDF
    : KdfId.NONE;
  const keyBit = keyLen === 256 ? 1 : 0;
  const hashBits = hash === "SHA-256"
    ? HashId.SHA256
    : hash === "SHA-384"
    ? HashId.SHA384
    : HashId.SHA512;
  const algoBit = AlgoId.AES_GCM; // only 0 currently
  return (kdfBits & 0b11) | ((keyBit & 1) << 2) | ((hashBits & 0b11) << 3) |
    ((algoBit & 1) << 5);
}
function unpackFlags(
  flags: number,
): {
  kdf: KdfAlgorithm;
  keyLen: 128 | 256;
  hash: HashAlg;
  algo: CipherAlgorithm;
} {
  const kdfBits = flags & 0b11;
  const keyBit = (flags >> 2) & 1;
  const hashBits = (flags >> 3) & 0b11;
  const algoBit = (flags >> 5) & 1;
  const kdf: KdfAlgorithm = kdfBits === KdfId.PBKDF2
    ? "PBKDF2"
    : kdfBits === KdfId.HKDF
    ? "HKDF"
    : "NONE";
  const keyLen: 128 | 256 = keyBit ? 256 : 128;
  const hash: HashAlg = hashBits === HashId.SHA256
    ? "SHA-256"
    : hashBits === HashId.SHA384
    ? "SHA-384"
    : "SHA-512";
  const algo: CipherAlgorithm = algoBit === AlgoId.AES_GCM
    ? "AES-GCM"
    : "AES-GCM";
  return { kdf, keyLen, hash, algo };
}

// --- Options you can pass to encryptString (they'll be embedded) ---
export interface CryptoOptions {
  ttl?: number | null;
  algorithm?: CipherAlgorithm; // default AES-GCM
  keyLengthBits?: 128 | 256; // 128 is faster
  kdf?: KdfAlgorithm; // PBKDF2 | HKDF | NONE
  pbkdf2Iterations?: number; // for PBKDF2
  hash?: HashAlg; // for PBKDF2/HKDF
  saltLengthBytes?: number; // default 16
  ivLengthBytes?: number; // default 12 for GCM
}

// --- Utilities ---
function ensureWebCryptoAvailable(): void {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new CryptoError(
      "UNSUPPORTED_ENVIRONMENT",
      "Web Crypto API (crypto.subtle) is not available in this environment.",
    );
  }
}

function encUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function base64ToUint8Array(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function arrayToBase64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let s = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk) as any);
  }
  return btoa(s);
}
function toBase64Url(bytes: Uint8Array): string {
  return arrayToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(
    /=+$/g,
    "",
  );
}
function fromBase64Url(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) & 3;
  if (pad) b64 += "=".repeat(pad);
  return base64ToUint8Array(b64);
}

// --- KDFs ---
async function importRawAesKey(
  raw: ArrayBufferView,
  algorithm: CipherAlgorithm,
  keyLengthBits: 128 | 256,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  if (raw.byteLength !== keyLengthBits / 8) {
    throw new CryptoError(
      "INVALID_KEY",
      `Raw key must be ${keyLengthBits / 8} bytes (got ${raw.byteLength}).`,
    );
  }
  return crypto.subtle.importKey(
    "raw",
    raw as BufferSource,
    { name: algorithm, length: keyLengthBits },
    false,
    usage,
  );
}

async function deriveKeyForEncrypt(
  secretKey: string,
  salt: Uint8Array,
  usage: KeyUsage[],
  kdf: KdfAlgorithm,
  hash: HashAlg,
  pbkdf2Iterations: number,
  algorithm: CipherAlgorithm,
  keyLengthBits: 128 | 256,
): Promise<CryptoKey> {
  if (kdf === "NONE") {
    // Use secret bytes directly as AES key (must be 16/32 bytes when UTF-8 encoded)
    const keyBytes = encUtf8(secretKey);
    return importRawAesKey(keyBytes, algorithm, keyLengthBits, usage);
  }
  if (kdf === "PBKDF2") {
    const pw = await crypto.subtle.importKey(
      "raw",
      encUtf8(secretKey) as BufferSource,
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: pbkdf2Iterations,
        hash,
      },
      pw,
      { name: algorithm, length: keyLengthBits },
      false,
      usage,
    );
  }
  // HKDF
  const ikm = await crypto.subtle.importKey(
    "raw",
    encUtf8(secretKey) as BufferSource,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: salt as BufferSource, info: new Uint8Array(), hash },
    ikm,
    { name: algorithm, length: keyLengthBits },
    false,
    usage,
  );
}

// --- Header build/parse ---
function buildHeader(
  kdf: KdfAlgorithm,
  keyLen: 128 | 256,
  hash: HashAlg,
  algo: CipherAlgorithm,
  saltLen: number,
  ivLen: number,
  pbkdf2Iterations: number,
  expirationTimestamp: number,
): Uint8Array {
  const hdr = new Uint8Array(HEADER_SIZE);
  hdr[0] = HEADER_MAGIC0;
  hdr[1] = HEADER_MAGIC1;
  hdr[2] = HEADER_VERSION;
  hdr[3] = packFlags(kdf, keyLen, hash, algo);
  hdr[4] = saltLen & 0xff;
  hdr[5] = ivLen & 0xff;
  // iters (uint32, big-endian)
  const dv = new DataView(hdr.buffer, hdr.byteOffset);
  dv.setUint32(6, pbkdf2Iterations >>> 0, false);
  // expiration (float64, big-endian)
  dv.setFloat64(10, expirationTimestamp, false);
  return hdr;
}

function parseHeader(buf: Uint8Array): {
  kdf: KdfAlgorithm;
  keyLen: 128 | 256;
  hash: HashAlg;
  algo: CipherAlgorithm;
  saltLen: number;
  ivLen: number;
  pbkdf2Iterations: number;
  expiration: number;
} {
  if (buf.length < HEADER_SIZE) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: header too short.",
    );
  }
  if (
    buf[0] !== HEADER_MAGIC0 || buf[1] !== HEADER_MAGIC1 ||
    buf[2] !== HEADER_VERSION
  ) {
    throw new CryptoError("INVALID_DATA", "Invalid header magic/version.");
  }
  const { kdf, keyLen, hash, algo } = unpackFlags(buf[3]);
  const saltLen = buf[4];
  const ivLen = buf[5];
  const dv = new DataView(buf.buffer, buf.byteOffset);
  const pbkdf2Iterations = dv.getUint32(6, false);
  const expiration = dv.getFloat64(10, false);
  return {
    kdf,
    keyLen,
    hash,
    algo,
    saltLen,
    ivLen,
    pbkdf2Iterations,
    expiration,
  };
}

/**
 * Encrypts a plaintext string with AES-GCM and embeds all necessary decryption
 * parameters (KDF, key length, hash, salt/IV sizes, iteration count, and TTL)
 * in an authenticated header inside the output token. The result is a compact,
 * base64url-encoded string that `decryptString` can decode without any options.
 *
 * How it works
 * - A compact binary header is prepended that includes:
 *   - KDF: "PBKDF2" | "HKDF" | "NONE"
 *   - Key length: 128 or 256 bits
 *   - Hash: "SHA-256" | "SHA-384" | "SHA-512" (for PBKDF2/HKDF)
 *   - Salt length and IV length
 *   - PBKDF2 iteration count (0 if not applicable)
 *   - Expiration timestamp (ms since epoch; Infinity when no TTL)
 * - The header is supplied as AES-GCM Additional Authenticated Data (AAD)
 *   so any tampering with embedded options causes decryption to fail.
 * - The output token layout is:
 *   [header | salt | iv | ciphertext], base64url-encoded (no padding).
 *
 * Security and performance guidance
 * - Use `kdf: "PBKDF2"` for password-like secrets (default; strongest for low-entropy input).
 * - Prefer `kdf: "HKDF"` for high-entropy secrets; it is much lighter than PBKDF2.
 * - Use `kdf: "NONE"` only with a pre-shared high-entropy key whose UTF-8 bytes are
 *   exactly 16 (AES-128) or 32 (AES-256); otherwise encryption will fail.
 * - `keyLengthBits: 128` is typically faster than 256 and is acceptable for most apps.
 *
 * Encoding
 * - Returns a base64url string (URL-safe; no `=` padding). No `encodeURIComponent` is needed.
 *
 * @async
 * @function encryptString
 * @param {string} plaintext
 *   The UTF-8 string to encrypt.
 * @param {string} secretKey
 *   The secret used for key derivation or as the raw AES key depending on `options.kdf`.
 *     - If `options.kdf` is "PBKDF2" or "HKDF", this may be any string (e.g., a password or high-entropy secret).
 *     - If `options.kdf` is "NONE", the UTF-8 byte length of `secretKey` must match the AES key size: 16 bytes for AES-128 or 32 bytes for AES-256.
 * @param {Object} [options] Optional encryption parameters to embed in the token. Decrypt will auto-discover these from the header.
 * @param {"AES-GCM"} [options.algorithm="AES-GCM"] The authenticated cipher algorithm. AES-GCM is used and embedded for integrity and interoperability.
 * @param {128|256} [options.keyLengthBits=256] AES key length in bits. 128 is often faster; 256 is the current default.
 * @param {"PBKDF2"|"HKDF"|"NONE"} [options.kdf="PBKDF2"]
 *   Key derivation function:
 *     - "PBKDF2": best for passwords; CPU-hard by design.
 *     - "HKDF": lightweight; use with high-entropy input.
 *     - "NONE": treat `secretKey` as a raw AES key (strict 16/32 UTF-8 bytes).
 * @param {number} [options.pbkdf2Iterations=100000] PBKDF2 iteration count (ignored unless `kdf` is "PBKDF2"). Lower values are faster but weaken resistance to guessing; consider using Web Workers to keep UI responsive for large iteration counts.
 * @param {"SHA-256"|"SHA-384"|"SHA-512"} [options.hash="SHA-256"] Hash function for PBKDF2/HKDF.
 * @param {number} [options.saltLengthBytes=16] Random salt length in bytes (0 is used when `kdf` is "NONE"). Included in the token.
 * @param {number} [options.ivLengthBytes=12] Random IV length in bytes. 12 (96-bit) is the recommended size for AES-GCM.
 * @param {number|null} [options.ttl=3600000] Time-to-live in milliseconds. Use `null` for no expiration (stored as Infinity in the header).
 *
 * @returns {Promise<string>}
 *   A base64url-encoded token containing the authenticated header, salt, IV, and ciphertext.
 *
 * @throws {CryptoError}
 *   - code: "UNSUPPORTED_ENVIRONMENT" when Web Crypto (`crypto.subtle`) is unavailable.
 *   - code: "ENCRYPTION_FAILED" for any failure during key derivation, parameter validation, or encryption.
 *
 * @example <caption>Default settings (PBKDF2 + AES-256-GCM, 1-hour TTL)</caption>
 * const token = await encryptString("hello world", "my strong passphrase");
 *
 * @example <caption>Faster settings for high-entropy secret (HKDF + AES-128-GCM)</caption>
 * const token = await encryptString("data", secret, {
 *   kdf: "HKDF",
 *   keyLengthBits: 128,
 *   ttl: null // no expiration
 * });
 *
 * @example <caption>Use a pre-shared raw key (kdf: "NONE")</caption>
 * // secretKey must be exactly 32 UTF-8 bytes for AES-256 (or 16 for AES-128)
 * const token = await encryptString("data", "0123456789abcdef0123456789abcdef", {
 *   kdf: "NONE",
 *   keyLengthBits: 256
 * });
 *
 * @see decryptString — Decrypts a token by reading the embedded header; no options required.
 */
export async function encryptString(
  plaintext: string,
  secretKey: string,
  options: CryptoOptions = {},
): Promise<string> {
  ensureWebCryptoAvailable();

  const {
    ttl = DEFAULT_TTL_MS,
    algorithm = DEFAULT_ALGO,
    keyLengthBits = DEFAULT_KEY_LEN,
    kdf = "PBKDF2",
    pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS,
    hash = "SHA-256",
    saltLengthBytes = DEFAULT_SALT_LEN,
    ivLengthBytes = DEFAULT_IV_LEN,
  } = options;

  try {
    const expiration = ttl === null ? Infinity : Date.now() + ttl;
    const salt = kdf === "NONE"
      ? new Uint8Array(0)
      : crypto.getRandomValues(new Uint8Array(saltLengthBytes));
    const iv = crypto.getRandomValues(new Uint8Array(ivLengthBytes));

    const header = buildHeader(
      kdf,
      keyLengthBits,
      hash,
      algorithm,
      salt.length,
      iv.length,
      kdf === "PBKDF2" ? pbkdf2Iterations : 0,
      expiration,
    );

    // Derive/import key
    const key = await deriveKeyForEncrypt(
      secretKey,
      salt,
      ["encrypt"],
      kdf,
      hash,
      pbkdf2Iterations,
      algorithm,
      keyLengthBits,
    );

    // Encrypt with header as AAD (authenticates embedded options)
    const ciphertext = await crypto.subtle.encrypt(
      { name: algorithm, iv, additionalData: header as BufferSource },
      key,
      encUtf8(plaintext) as BufferSource,
    );

    // Compose: [header | salt | iv | ciphertext]
    const ct = new Uint8Array(ciphertext);
    const out = new Uint8Array(
      header.length + salt.length + iv.length + ct.length,
    );
    let off = 0;
    out.set(header, off);
    off += header.length;
    out.set(salt, off);
    off += salt.length;
    out.set(iv, off);
    off += iv.length;
    out.set(ct, off);

    return toBase64Url(out);
  } catch (error: any) {
    throw new CryptoError(
      "ENCRYPTION_FAILED",
      `Encryption failed: ${error.message}`,
      error,
    );
  }
}

/**
 * Decrypts a string that was encrypted with `encryptString`, checking its TTL.
 *
 * No options needed; everything is embedded in the encrypted data.
 *
 * @param encryptedData The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string.
 * @throws {CryptoError}
 */
export async function decryptString(
  encryptedData: string,
  secretKey: string,
): Promise<string> {
  ensureWebCryptoAvailable();

  // Decode
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(encryptedData);
  } catch (error: any) {
    // try legacy non-url-safe base64
    try {
      bytes = base64ToUint8Array(encryptedData);
    } catch {
      throw new CryptoError(
        "INVALID_DATA",
        "Invalid encrypted data: base64 decode failed.",
        error,
      );
    }
  }

  // Detect header magic; if absent, fall back to legacy format for backward compatibility
  const hasHeader = bytes.length >= HEADER_SIZE && bytes[0] === HEADER_MAGIC0 &&
    bytes[1] === HEADER_MAGIC1 && bytes[2] === HEADER_VERSION;

  if (!hasHeader) {
    // Legacy layout: [iters(4)|exp(8)|salt(16)|iv(12)|ciphertext], AES-256-GCM, PBKDF2/SHA-256
    const ITERATIONS_LENGTH_BYTES = 4;
    const EXPIRATION_LENGTH_BYTES = 8;
    const SALT_LENGTH_BYTES = 16;
    const IV_LENGTH_BYTES = 12;
    const minLen = ITERATIONS_LENGTH_BYTES + EXPIRATION_LENGTH_BYTES +
      SALT_LENGTH_BYTES + IV_LENGTH_BYTES;
    if (bytes.length < minLen) {
      throw new CryptoError(
        "INVALID_DATA",
        "Invalid encrypted data: payload is too short.",
      );
    }
    let offset = 0;
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    const iters = dv.getUint32(offset, false);
    offset += ITERATIONS_LENGTH_BYTES;
    const expiration = dv.getFloat64(offset, false);
    offset += EXPIRATION_LENGTH_BYTES;
    if (Date.now() > expiration) {
      throw new CryptoError("EXPIRED", "The encrypted data has expired.");
    }
    const salt = bytes.subarray(offset, offset + SALT_LENGTH_BYTES);
    offset += SALT_LENGTH_BYTES;
    const iv = bytes.subarray(offset, offset + IV_LENGTH_BYTES) as BufferSource;
    offset += IV_LENGTH_BYTES;
    const ciphertext = bytes.subarray(offset) as BufferSource;
    const key = await deriveKeyForEncrypt(
      secretKey,
      salt,
      ["decrypt"],
      "PBKDF2",
      "SHA-256",
      iters,
      "AES-GCM",
      256,
    );
    try {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext,
      );
      return new TextDecoder().decode(pt);
    } catch (error: any) {
      throw new CryptoError(
        "DECRYPTION_FAILED",
        "Decryption failed. Wrong key or tampered data.",
        error,
      );
    }
  }

  // New header path
  const header = parseHeader(bytes.subarray(0, HEADER_SIZE));
  const {
    kdf,
    keyLen,
    hash,
    algo,
    saltLen,
    ivLen,
    pbkdf2Iterations,
    expiration,
  } = header;

  if (Date.now() > expiration) {
    throw new CryptoError("EXPIRED", "The encrypted data has expired.");
  }

  const minLen = HEADER_SIZE + saltLen + ivLen + 1;
  if (bytes.length < minLen) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: truncated payload.",
    );
  }

  let offset = HEADER_SIZE;
  const salt = bytes.subarray(offset, offset + saltLen);
  offset += saltLen;
  const iv = bytes.subarray(offset, offset + ivLen) as BufferSource;
  offset += ivLen;
  const ciphertext = bytes.subarray(offset) as BufferSource;

  // Derive/import key using embedded options
  const key = await deriveKeyForEncrypt(
    secretKey,
    salt,
    ["decrypt"],
    kdf,
    hash,
    pbkdf2Iterations,
    algo,
    keyLen,
  );

  try {
    const pt = await crypto.subtle.decrypt(
      {
        name: algo,
        iv,
        additionalData: bytes.subarray(0, HEADER_SIZE) as BufferSource,
      },
      key,
      ciphertext,
    );
    return new TextDecoder().decode(pt);
  } catch (error: any) {
    throw new CryptoError(
      "DECRYPTION_FAILED",
      "Decryption failed. Wrong key or tampered data.",
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
  const data = new TextEncoder().encode(objectString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// // --- Custom Error Handling ---

// import { createCanonicalString } from "../utils";

// /**
//  * A set of specific error codes for cryptographic operations.
//  */
// export type CryptoErrorCode =
//   | "UNSUPPORTED_ENVIRONMENT"
//   | "ENCRYPTION_FAILED"
//   | "DECRYPTION_FAILED"
//   | "INVALID_DATA"
//   | "EXPIRED";

// /**
//  * Custom error class for handling specific cryptographic failures.
//  * This allows for robust error handling using `instanceof` or by checking the `code`.
//  */
// export class CryptoError extends Error {
//   public readonly code: CryptoErrorCode;
//   public readonly cause?: Error;

//   constructor(code: CryptoErrorCode, message: string, cause?: Error) {
//     super(message);
//     this.name = "CryptoError";
//     this.code = code;
//     this.cause = cause;
//   }
// }

// // --- Cryptographic Constants ---
// const ALGORITHM_NAME = "AES-GCM";
// const KEY_DERIVATION_ALGORITHM = "PBKDF2";
// const KEY_LENGTH_BITS = 256;
// const SALT_LENGTH_BYTES = 16;
// const IV_LENGTH_BYTES = 12;
// const PBKDF2_HASH = "SHA-256";
// const EXPIRATION_LENGTH_BYTES = 8; // 64-bit float for the timestamp
// const ITERATIONS_LENGTH_BYTES = 4; // 32-bit unsigned integer for iterations

// // --- Default Configuration ---
// const DEFAULT_TTL_MS: number = 60 * 60 * 1000; // 1 hour
// const DEFAULT_PBKDF2_ITERATIONS = 100000;

// // --- Helper Functions ---

// function arrayBufferToBase64(buffer: ArrayBuffer): string {
//   const bytes = new Uint8Array(buffer);
//   const chunkSize = 8192; // Process in 8KB chunks
//   let result = "";

//   for (let i = 0; i < bytes.length; i += chunkSize) {
//     const chunk = bytes.subarray(i, i + chunkSize);
//     // String.fromCharCode.apply is more performant than a spread operator for this use case.
//     result += String.fromCharCode.apply(null, chunk as any);
//   }

//   return btoa(result);
// }

// function base64ToArrayBuffer(base64: string): ArrayBuffer {
//   const binaryString = atob(base64);
//   const len = binaryString.length;
//   const bytes = new Uint8Array(len);
//   for (let i = 0; i < len; i++) {
//     bytes[i] = binaryString.charCodeAt(i);
//   }
//   return bytes.buffer;
// }

// function ensureWebCryptoAvailable(): void {
//   if (typeof crypto === "undefined" || !crypto.subtle) {
//     throw new CryptoError(
//       "UNSUPPORTED_ENVIRONMENT",
//       "Web Crypto API (crypto.subtle) is not available in this environment.",
//     );
//   }
// }

// /**
//  * Derives a cryptographic key from a secret string using PBKDF2.
//  * @internal
//  */
// async function _deriveKey(
//   secretKey: string,
//   salt: BufferSource,
//   iterations: number,
//   usage: KeyUsage[],
// ): Promise<CryptoKey> {
//   const passwordKeyMaterial = await crypto.subtle.importKey(
//     "raw",
//     new TextEncoder().encode(secretKey),
//     { name: KEY_DERIVATION_ALGORITHM },
//     false,
//     ["deriveKey"],
//   );

//   return crypto.subtle.deriveKey(
//     {
//       name: KEY_DERIVATION_ALGORITHM,
//       salt,
//       iterations,
//       hash: PBKDF2_HASH,
//     },
//     passwordKeyMaterial,
//     { name: ALGORITHM_NAME, length: KEY_LENGTH_BITS },
//     false,
//     usage,
//   );
// }

// /**
//  * Encrypts a plaintext string using AES-256-GCM, embedding TTL and iteration count.
//  *
//  * @param plaintext The string to encrypt.
//  * @param secretKey The secret key for key derivation.
//  * @param options Configuration for TTL and PBKDF2 iterations.
//  * @param options.ttl The Time-To-Live in milliseconds. Pass `null` for no expiration. Defaults to 1 hour.
//  * @param options.pbkdf2Iterations The number of iterations for key derivation.
//  *        **WARNING**: Reducing this from the default weakens security.
//  * @returns A Promise resolving to a URL-safe, Base64 encoded string.
//  * @throws {CryptoError} If the environment is unsupported or encryption fails.
//  */
// export async function encryptString(
//   plaintext: string,
//   secretKey: string,
//   options: { ttl?: number | null; pbkdf2Iterations?: number } = {},
// ): Promise<string> {
//   ensureWebCryptoAvailable();

//   const {
//     ttl = DEFAULT_TTL_MS,
//     pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS,
//   } = options;

//   try {
//     // 1. Store the iteration count and expiration timestamp.
//     const iterationsBuffer = new ArrayBuffer(ITERATIONS_LENGTH_BYTES);
//     new DataView(iterationsBuffer).setUint32(0, pbkdf2Iterations, false); // Big-endian

//     const expirationTimestamp = ttl === null ? Infinity : Date.now() + ttl;
//     const expirationBuffer = new ArrayBuffer(EXPIRATION_LENGTH_BYTES);
//     new DataView(expirationBuffer).setFloat64(0, expirationTimestamp, false);

//     // 2. Generate salt and IV.
//     const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
//     const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

//     // 3. Derive the encryption key.
//     const derivedEncryptionKey = await _deriveKey(
//       secretKey,
//       salt,
//       pbkdf2Iterations,
//       ["encrypt"],
//     );

//     // 4. Encrypt the data.
//     const encodedPlaintext = new TextEncoder().encode(plaintext);
//     const ciphertext = await crypto.subtle.encrypt(
//       { name: ALGORITHM_NAME, iv },
//       derivedEncryptionKey,
//       encodedPlaintext,
//     );

//     // 5. Combine [iterations, expiration, salt, iv, ciphertext] into a single buffer.
//     const combinedData = new Uint8Array(
//       ITERATIONS_LENGTH_BYTES +
//         EXPIRATION_LENGTH_BYTES +
//         salt.length +
//         iv.length +
//         ciphertext.byteLength,
//     );
//     let offset = 0;
//     combinedData.set(new Uint8Array(iterationsBuffer), offset);
//     offset += ITERATIONS_LENGTH_BYTES;
//     combinedData.set(new Uint8Array(expirationBuffer), offset);
//     offset += EXPIRATION_LENGTH_BYTES;
//     combinedData.set(salt, offset);
//     offset += salt.length;
//     combinedData.set(iv, offset);
//     offset += iv.length;
//     combinedData.set(new Uint8Array(ciphertext), offset);

//     return encodeURIComponent(arrayBufferToBase64(combinedData.buffer));
//   } catch (error: any) {
//     throw new CryptoError(
//       "ENCRYPTION_FAILED",
//       `Encryption failed: ${error.message}`,
//       error,
//     );
//   }
// }

// /**
//  * Decrypts a string that was encrypted with encryptString, checking its TTL.
//  * The iteration count is automatically extracted from the payload.
//  *
//  * @param encryptedDataB64 The Base64 encoded string from encryptString.
//  * @param secretKey The *same* secret key used for encryption.
//  * @returns A Promise resolving to the original plaintext string.
//  * @throws {CryptoError}
//  */
// export async function decryptString(
//   encryptedDataB64: string,
//   secretKey: string,
// ): Promise<string> {
//   ensureWebCryptoAvailable();

//   let combinedData: Uint8Array;
//   try {
//     const combinedDataBuffer = base64ToArrayBuffer(
//       decodeURIComponent(encryptedDataB64),
//     );
//     combinedData = new Uint8Array(combinedDataBuffer);
//   } catch (error: any) {
//     throw new CryptoError(
//       "INVALID_DATA",
//       "Invalid encrypted data: failed to decode base64 payload.",
//       error,
//     );
//   }

//   const minLength = ITERATIONS_LENGTH_BYTES +
//     EXPIRATION_LENGTH_BYTES +
//     SALT_LENGTH_BYTES +
//     IV_LENGTH_BYTES;
//   if (combinedData.length < minLength) {
//     throw new CryptoError(
//       "INVALID_DATA",
//       "Invalid encrypted data: payload is too short.",
//     );
//   }

//   // 1. Extract iterations and expiration.
//   let offset = 0;
//   const iterationsView = new DataView(
//     combinedData.buffer,
//     offset,
//     ITERATIONS_LENGTH_BYTES,
//   );
//   const pbkdf2Iterations = iterationsView.getUint32(0, false);
//   offset += ITERATIONS_LENGTH_BYTES;

//   const expirationView = new DataView(
//     combinedData.buffer,
//     offset,
//     EXPIRATION_LENGTH_BYTES,
//   );
//   const expirationTimestamp = expirationView.getFloat64(0, false);
//   offset += EXPIRATION_LENGTH_BYTES;

//   // 2. Check for expiration.
//   if (Date.now() > expirationTimestamp) {
//     throw new CryptoError("EXPIRED", "The encrypted data has expired.");
//   }

//   // 3. Extract salt, IV, and ciphertext.
//   const salt = combinedData.subarray(
//     offset,
//     offset + SALT_LENGTH_BYTES,
//   ) as BufferSource;
//   offset += SALT_LENGTH_BYTES;
//   const iv = combinedData.subarray(
//     offset,
//     offset + IV_LENGTH_BYTES,
//   ) as BufferSource;
//   offset += IV_LENGTH_BYTES;
//   const ciphertext = combinedData.subarray(offset) as BufferSource;

//   // 4. Derive the decryption key using the extracted iteration count.
//   const derivedDecryptionKey = await _deriveKey(
//     secretKey,
//     salt,
//     pbkdf2Iterations,
//     ["decrypt"],
//   );

//   try {
//     // 5. Decrypt the ciphertext.
//     const decryptedBuffer = await crypto.subtle.decrypt(
//       { name: ALGORITHM_NAME, iv: iv },
//       derivedDecryptionKey,
//       ciphertext,
//     );
//     return new TextDecoder().decode(decryptedBuffer);
//   } catch (error: any) {
//     throw new CryptoError(
//       "DECRYPTION_FAILED",
//       "Decryption failed. This is often caused by a wrong secret key or tampered data.",
//       error,
//     );
//   }
// }

// export async function hashObject(obj: any): Promise<string> {
//   const objectString = createCanonicalString(obj);

//   // Use the Web Crypto API, which is available in modern browsers and Node.js (v15.7+)
//   const encoder = new TextEncoder();
//   const data = encoder.encode(objectString);
//   const hashBuffer = await crypto.subtle.digest("SHA-256", data);
//   const hashArray = Array.from(new Uint8Array(hashBuffer));
//   const hashHex = hashArray
//     .map((b) => b.toString(16).padStart(2, "0"))
//     .join("");

//   return hashHex;
// }
