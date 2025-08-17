import { test, expect } from "bun:test";
import { encryptString, decryptString, hashObject } from "../src/cryptography";

test("encryptString and decryptString should work correctly", async () => {
    const plaintext = "Hello, World!";
    const secretKey = "supersecret";
    const encrypted = await encryptString(plaintext, secretKey);
    const decrypted = await decryptString(encrypted, secretKey);
    expect(decrypted).toBe(plaintext);
});

test("decryptString should fail with wrong key", async () => {
    const plaintext = "Hello, World!";
    const secretKey = "supersecret";
    const wrongKey = "wrongsecret";
    const encrypted = await encryptString(plaintext, secretKey);
    await expect(decryptString(encrypted, wrongKey)).rejects.toThrow();
});

test("decryptString should fail with tampered data", async () => {
    const plaintext = "Hello, World!";
    const secretKey = "supersecret";
    const encrypted = await encryptString(plaintext, secretKey);
    const tampered = encrypted.slice(0, -1) + "a";
    await expect(decryptString(tampered, secretKey)).rejects.toThrow();
});

test("decryptString should respect TTL", async () => {
    const plaintext = "Hello, World!";
    const secretKey = "supersecret";
    const encrypted = await encryptString(plaintext, secretKey, 100); // 100ms TTL
    
    // Should decrypt successfully immediately
    const decrypted = await decryptString(encrypted, secretKey);
    expect(decrypted).toBe(plaintext);

    // Wait for TTL to expire
    await new Promise(resolve => setTimeout(resolve, 150));

    // Should fail after TTL expiry
    await expect(decryptString(encrypted, secretKey)).rejects.toThrow("The encrypted data has expired.");
});


test("hashObject should produce consistent hash for same object", async () => {
    const obj1 = { a: 1, b: { c: 2, d: 3 } };
    const obj2 = { b: { d: 3, c: 2 }, a: 1 };
    const hash1 = await hashObject(obj1);
    const hash2 = await hashObject(obj2);
    expect(hash1).toBe(hash2);
});

test("hashObject should produce different hashes for different objects", async () => {
    const obj1 = { a: 1, b: 2 };
    const obj2 = { a: 1, b: 3 };
    const hash1 = await hashObject(obj1);
    const hash2 = await hashObject(obj2);
    expect(hash1).not.toBe(hash2);
});

test("hashObject should handle strings correctly", async () => {
    const str = "hello world";
    const hash = await hashObject(str);
    expect(hash).toBe("9ddefe4435b21d901439e546d54a14a175a3493b9fd8fbf38d9ea6d3cbf70826");
});