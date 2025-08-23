import { describe, expect, test } from "bun:test";

import {
  CryptoError,
  decryptString,
  encryptString,
  hashObject,
} from "../src/crypto";

describe("encryptString and decryptString", () => {
    const plaintext = "Hello, Streamline.js!";
    const secretKey = "a-very-secret-key";

    test("should encrypt and decrypt successfully with a valid key", async () => {
        const encrypted = await encryptString(plaintext, secretKey);
        const decrypted = await decryptString(encrypted, secretKey);
        expect(decrypted).toBe(plaintext);
    });

    test("should fail to decrypt with a wrong secret key", async () => {
        const wrongKey = "not-the-right-key";
        const encrypted = await encryptString(plaintext, secretKey);

        const promise = decryptString(encrypted, wrongKey);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "DECRYPTION_FAILED",
        );
    });

    test("should fail to decrypt tampered data", async () => {
        const encrypted = await encryptString(plaintext, secretKey);
        const tampered = encrypted.slice(0, -1) + "a"; // Alter the last character

        const promise = decryptString(tampered, secretKey);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty("code", "INVALID_DATA");
    });

    test("should fail with DECRYPTION_FAILED for tampered ciphertext", async () => {
        const encrypted = await encryptString(plaintext, secretKey);

        // Decode the payload
        const decodedB64 = decodeURIComponent(encrypted);
        const binaryString = atob(decodedB64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        // Tamper with the last byte of the ciphertext
        bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff; // Flip all bits

        // Re-encode
        const tamperedBinaryString = String.fromCharCode(...bytes);
        const tamperedB64 = btoa(tamperedBinaryString);
        const tamperedEncrypted = encodeURIComponent(tamperedB64);

        const promise = decryptString(tamperedEncrypted, secretKey);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "DECRYPTION_FAILED",
        );
    });

    test("should fail if the payload is too short", async () => {
        const shortPayload = "short";
        const promise = decryptString(shortPayload, secretKey);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty("code", "INVALID_DATA");
    });

    describe("Time-To-Live (TTL)", () => {
        test("should respect a short TTL and expire", async () => {
            const encrypted = await encryptString(plaintext, secretKey, {
                ttl: 200, // 200ms TTL
            });

            // Should decrypt successfully immediately
            const decrypted = await decryptString(encrypted, secretKey);
            expect(decrypted).toBe(plaintext);

            // Wait for TTL to expire
            await new Promise((resolve) => setTimeout(resolve, 300));

            // Should fail after TTL expiry
            const promise = decryptString(encrypted, secretKey);
            await expect(promise).rejects.toThrow(CryptoError);
            await expect(promise).rejects.toHaveProperty("code", "EXPIRED");
        });

        test("should not expire when TTL is null", async () => {
            const encrypted = await encryptString(plaintext, secretKey, {
                ttl: null,
            });
            await new Promise((resolve) => setTimeout(resolve, 100)); // Wait a bit
            const decrypted = await decryptString(encrypted, secretKey);
            expect(decrypted).toBe(plaintext);
        });
    });
});

describe("hashObject", () => {
    test("should produce a consistent hash for the same object with different key orders", async () => {
        const obj1 = { a: 1, b: { c: 2, d: 3 } };
        const obj2 = { b: { d: 3, c: 2 }, a: 1 };
        const hash1 = await hashObject(obj1);
        const hash2 = await hashObject(obj2);
        expect(hash1).toBe(hash2);
        expect(hash1).toBe(
            "932875ab5b23eb47bb2711f951d85ba23eef4b50c3e2eb6b5f3f9b9ac1217c6b",
        );
    });

    test("should produce different hashes for different objects", async () => {
        const obj1 = { a: 1, b: 2 };
        const obj2 = { a: 1, b: 3 };
        const hash1 = await hashObject(obj1);
        const hash2 = await hashObject(obj2);
        expect(hash1).not.toBe(hash2);
    });

    test("should handle various data types correctly", async () => {
        const strHash = await hashObject("hello world");
        expect(strHash).toBe(
            "9ddefe4435b21d901439e546d54a14a175a3493b9fd8fbf38d9ea6d3cbf70826",
        );

        const numHash = await hashObject(12345);
        expect(numHash).toBe(
            "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
        );

        const boolHash = await hashObject(true);
        expect(boolHash).toBe(
            "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        );

        const nullHash = await hashObject(null);
        expect(nullHash).toBe(
            "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
        );
    });

    test("should produce a consistent hash for an array", async () => {
        const arr1 = [1, { a: 2 }, [3, 4]];
        const arr2 = [1, { a: 2 }, [3, 4]];
        const hash1 = await hashObject(arr1);
        const hash2 = await hashObject(arr2);
        expect(hash1).toBe(hash2);
    });
});

describe("hashObject with advanced types", () => {
    test("should produce a consistent hash for objects with Dates", async () => {
        const obj1 = { a: new Date(0), b: 1 };
        const obj2 = { b: 1, a: new Date(0) };
        const hash1 = await hashObject(obj1);
        const hash2 = await hashObject(obj2);
        expect(hash1).toBe(hash2);
    });

    test("should produce a consistent hash for objects with RegExps", async () => {
        const obj1 = { a: /hello/gi, b: 1 };
        const obj2 = { b: 1, a: /hello/gi };
        const hash1 = await hashObject(obj1);
        const hash2 = await hashObject(obj2);
        expect(hash1).toBe(hash2);
    });

    test("should produce a consistent hash for Maps with different insertion orders", async () => {
        const map1 = new Map([["a", 1], ["b", 2]]);
        const map2 = new Map([["b", 2], ["a", 1]]);
        const hash1 = await hashObject(map1);
        const hash2 = await hashObject(map2);
        expect(hash1).toBe(hash2);
    });

    test("should produce a consistent hash for Sets with different insertion orders", async () => {
        const set1 = new Set([1, 2, 3]);
        const set2 = new Set([3, 2, 1]);
        const hash1 = await hashObject(set1);
        const hash2 = await hashObject(set2);
        expect(hash1).toBe(hash2);
    });

    test("should handle circular references gracefully", async () => {
        const obj: any = { a: 1 };
        obj.b = obj; // Circular reference
        const hash = await hashObject(obj);

        const obj2: any = { a: 1 };
        obj2.b = obj2;
        const hash2 = await hashObject(obj2);

        expect(hash).toBe(hash2);
        expect(hash).toBe(
            "7ca81485219c7d71082025aa7bb6596d025b5ef7247384f94d9f2b0c4ee50c1b",
        );
    });

    test("should handle BigInt, Symbol, and undefined values", async () => {
        const symbol = Symbol("test");
        const obj1 = { a: 1n, b: undefined, c: symbol };
        const obj2 = { c: symbol, b: undefined, a: 1n };
        const hash1 = await hashObject(obj1);
        const hash2 = await hashObject(obj2);
        expect(hash1).toBe(hash2);
    });
});
