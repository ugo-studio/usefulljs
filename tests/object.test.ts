import { describe, expect, test } from "bun:test";

import {
  areEqual,
  areNotEqual,
  getValue,
  omit,
  pick,
  toCanonicalString,
} from "../src/lib/object";

describe("toCanonicalString", () => {
    test("should return a consistent string for the same object", () => {
        const obj = { a: 1, b: "hello" };
        expect(toCanonicalString(obj)).toBe('{"a":1,"b":"hello"}');
    });

    test("should handle different key orders", () => {
        const obj1 = { a: 1, b: "hello" };
        const obj2 = { b: "hello", a: 1 };
        expect(toCanonicalString(obj1)).toBe(toCanonicalString(obj2));
    });

    test("should handle nested objects", () => {
        const obj = { a: 1, b: { c: 2, d: 3 } };
        expect(toCanonicalString(obj)).toBe('{"a":1,"b":{"c":2,"d":3}}');
    });

    test("should handle arrays", () => {
        const arr = [1, "hello", { a: 1 }];
        expect(toCanonicalString(arr)).toBe('[1,"hello",{"a":1}]');
    });

    test("should handle different data types", () => {
        expect(toCanonicalString(123)).toBe("123");
        expect(toCanonicalString("hello")).toBe('"hello"');
        expect(toCanonicalString(true)).toBe("true");
        expect(toCanonicalString(null)).toBe("null");
    });
});

describe("areEqual", () => {
    test("should return true for equal objects", () => {
        const obj1 = { a: 1, b: 2 };
        const obj2 = { b: 2, a: 1 };
        expect(areEqual(obj1, obj2)).toBe(true);
    });

    test("should return true for multiple equal values", () => {
        expect(areEqual(1, 1, 1, 1)).toBe(true);
        const obj = { a: 1 };
        expect(areEqual(obj, obj, obj)).toBe(true);
    });

    test("should return false for unequal objects", () => {
        const obj1 = { a: 1 };
        const obj2 = { a: 2 };
        expect(areEqual(obj1, obj2)).toBe(false);
    });

    test("should return false if at least one value is different", () => {
        expect(areEqual(1, 1, 2, 1)).toBe(false);
    });

    test("should handle different data types", () => {
        expect(areEqual("hello", "hello")).toBe(true);
        expect(areEqual(123, 123)).toBe(true);
        expect(areEqual(true, true)).toBe(true);
        expect(areEqual(null, null)).toBe(true);
        expect(areEqual(undefined, undefined)).toBe(true);
    });

    test("should return true for an empty set of values", () => {
        expect(areEqual()).toBe(true);
    });

    test("should return true for a single value", () => {
        expect(areEqual({ a: 1 })).toBe(true);
    });
});

describe("areNotEqual", () => {
    test("should return false for equal objects", () => {
        const obj1 = { a: 1, b: 2 };
        const obj2 = { b: 2, a: 1 };
        expect(areNotEqual(obj1, obj2)).toBe(false);
    });

    test("should return false for multiple equal values", () => {
        expect(areNotEqual(1, 1, 1, 1)).toBe(false);
    });

    test("should return true for unequal objects", () => {
        const obj1 = { a: 1 };
        const obj2 = { a: 2 };
        expect(areNotEqual(obj1, obj2)).toBe(true);
    });

    test("should return true if at least one value is different", () => {
        expect(areNotEqual(1, 1, 2, 1)).toBe(true);
    });

    test("should return false for an empty set of values", () => {
        expect(areNotEqual()).toBe(false);
    });

    test("should return false for a single value", () => {
        expect(areNotEqual({ a: 1 })).toBe(false);
    });
});

describe("getValue", () => {
    const obj = { a: { b: [{ c: 1 }, { d: 2 }] }, e: null };

    test("should get a value from a simple path", () => {
        expect(getValue(obj, "a")).toEqual({ b: [{ c: 1 }, { d: 2 }] });
    });

    test("should get a value from a nested path", () => {
        expect(getValue(obj, "a.b")).toEqual([{ c: 1 }, { d: 2 }]);
    });

    test("should get a value from a path with array indices", () => {
        expect(getValue(obj, "a.b.0.c")).toBe(1);
        expect(getValue(obj, "a.b[1].d")).toBe(2);
    });

    test("should return undefined for a non-existent path", () => {
        expect(getValue(obj, "a.c")).toBeUndefined();
        expect(getValue(obj, "a.b.2")).toBeUndefined();
    });

    test("should return undefined for a path into a null or undefined value", () => {
        expect(getValue(obj, "e.f")).toBeUndefined();
        expect(getValue(obj, "f.g")).toBeUndefined();
    });
});

describe("pick", () => {
    const obj = { a: 1, b: "hello", c: true };

    test("should pick specified properties from an object", () => {
        const picked = pick(obj, ["a", "c"]);
        expect(picked).toEqual({ a: 1, c: true });
    });

    test("should return an empty object if no keys are picked", () => {
        const picked = pick(obj, []);
        expect(picked).toEqual({});
    });

    test("should ignore keys that don't exist on the object", () => {
        const picked = pick(obj, ["a", "d" as any]);
        expect(picked).toEqual({ a: 1 });
    });
});

describe("omit", () => {
    const obj = { a: 1, b: "hello", c: true };

    test("should omit specified properties from an object", () => {
        const omitted = omit(obj, ["b"]);
        expect(omitted).toEqual({ a: 1, c: true });
    });

    test("should return an identical object if no keys are omitted", () => {
        const omitted = omit(obj, []);
        expect(omitted).toEqual(obj);
    });

    test("should ignore keys that don't exist on the object", () => {
        const omitted = omit(obj, ["d" as any, "e" as any]);
        expect(omitted).toEqual(obj);
    });
});
