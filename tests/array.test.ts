import { describe, expect, test } from "bun:test";

import { ArraySL } from "../src/array";

describe("ArraySL Constructor and Core", () => {
    test("should create an instance from an array", () => {
        const arr = new ArraySL([1, 2, 3]);
        expect(arr).toBeInstanceOf(ArraySL);
        expect(arr.length).toBe(3);
        expect(arr.first).toBe(1);
    });

    test("should create an empty instance", () => {
        const arr = new ArraySL();
        expect(arr.length).toBe(0);
    });

    test("should create an instance with a specified length", () => {
        const arr = new ArraySL(5);
        expect(arr.length).toBe(5);
    });

    test("method chaining should be preserved (Symbol.species)", () => {
        const arr = new ArraySL([
            { id: 1, group: "a" },
            { id: 2, group: "b" },
            { id: 3, group: "a" },
        ]);
        const result = arr.filter((item) => item.group === "a");
        expect(result).toBeInstanceOf(ArraySL);
        expect(result.length).toBe(2);
        expect(result.first?.id).toBe(1);
    });
});

describe("ArraySL Getters", () => {
    test("getters should work on a non-empty array", () => {
        const arr = new ArraySL([1, 2, 3, 4, 5]);
        expect(arr.first).toBe(1);
        expect(arr.last).toBe(5);
        const randomElement = arr.random;
        expect(arr.includes(randomElement!)).toBe(true);
    });

    test("getters should return undefined for an empty array", () => {
        const arr = new ArraySL<number>();
        expect(arr.first).toBeUndefined();
        expect(arr.last).toBeUndefined();
        expect(arr.random).toBeUndefined();
    });
});

describe("ArraySL.unique", () => {
    test("should return unique elements using default accessor", () => {
        const arr = new ArraySL([1, 2, 2, 3, 1, 4]);
        const uniqueArr = arr.unique();
        expect(uniqueArr).toEqual(new ArraySL([1, 2, 3, 4]));
    });

    test("should return unique elements using a custom accessor", () => {
        const arr = new ArraySL([{ id: 1 }, { id: 2 }, { id: 1 }]);
        const uniqueArr = arr.unique({ accessor: (item) => item.id });
        expect(uniqueArr.length).toBe(2);
        expect(uniqueArr.map((i) => i.id)).toEqual([1, 2]);
    });

    test("should return an empty array if the original is empty", () => {
        const arr = new ArraySL();
        expect(arr.unique()).toEqual(new ArraySL());
    });

    test("should handle an array with no duplicates", () => {
        const arr = new ArraySL([1, 2, 3]);
        expect(arr.unique()).toEqual(new ArraySL([1, 2, 3]));
    });
});

describe("ArraySL.duplicates", () => {
    const complexArr = new ArraySL([
        { id: 1, val: "a" }, // 1
        { id: 2, val: "b" }, // 2
        { id: 1, val: "c" }, // 3
        { id: 3, val: "d" }, // 4
        { id: 1, val: "e" }, // 5
        { id: 2, val: "f" }, // 6
    ]);

    test("should return no duplicates for a unique array", () => {
        const arr = new ArraySL([1, 2, 3]);
        expect(arr.duplicates().length).toBe(0);
    });

    test("should return an empty array for an empty array", () => {
        const arr = new ArraySL();
        expect(arr.duplicates().length).toBe(0);
    });

    describe("mode: 'all'", () => {
        test("should get all occurrences of duplicated items", () => {
            const arr = new ArraySL([1, 2, 1, 3, 1, 2]);
            const result = arr.duplicates({ mode: "all" });
            expect(result.sort()).toEqual([1, 1, 1, 2, 2]);
        });

        test("should work with a custom accessor", () => {
            const result = complexArr.duplicates({
                accessor: (i) => i.id,
                mode: "all",
            });
            expect(result.map((i) => i.val).sort()).toEqual([
                "a",
                "b",
                "c",
                "e",
                "f",
            ]);
        });
    });

    describe("mode: 'first'", () => {
        test("should get only the first instance of each duplicated item", () => {
            const arr = new ArraySL([1, 2, 1, 3, 1, 2]);
            const result = arr.duplicates({ mode: "first" });
            expect(result.sort()).toEqual([1, 2]);
        });

        test("should work with a custom accessor", () => {
            const result = complexArr.duplicates({
                accessor: (i) => i.id,
                mode: "first",
            });
            expect(result.map((i) => i.val).sort()).toEqual(["a", "b"]);
        });
    });

    describe("mode: 'subsequent'", () => {
        test("should get only the duplicates that appear after the first one", () => {
            const arr = new ArraySL([1, 2, 1, 3, 1, 2]);
            const result = arr.duplicates({ mode: "subsequent" });
            expect(result.sort()).toEqual([1, 1, 2]);
        });

        test("should work with a custom accessor", () => {
            const result = complexArr.duplicates({
                accessor: (i) => i.id,
                mode: "subsequent",
            });
            expect(result.map((i) => i.val).sort()).toEqual(["c", "e", "f"]);
        });
    });
});

describe("ArraySL.middle", () => {
    test("should find the single middle item in an odd-length array", () => {
        const arr = new ArraySL([10, 20, 5, 30, 15]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArraySL([5]));
    });

    test("should find the two middle items in an even-length array", () => {
        const evenArr = new ArraySL([10, 20, 5, 30]);
        const middle = evenArr.middle();
        expect(middle).toEqual(new ArraySL([20, 5]));
    });

    test("should return an empty array for an empty input array", () => {
        const arr = new ArraySL([]);
        const middle = arr.middle();
        expect(middle.length).toBe(0);
    });

    test("should return the single item for an array with one element", () => {
        const arr = new ArraySL([42]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArraySL([42]));
    });

    test("should return both items for an array with two elements", () => {
        const arr = new ArraySL([1, 2]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArraySL([1, 2]));
    });
});

describe("ArraySL.mostFrequent", () => {
    test("should find the mode in a simple case", () => {
        const arr = new ArraySL([{ val: "a" }, { val: "b" }, { val: "a" }]);
        const mode = arr.mostFrequent((item) => item.val);
        expect(mode.length).toBe(2);
        expect(mode.every((item) => item.val === "a")).toBe(true);
    });

    test("should find the mode with default accessor (item itself)", () => {
        const arr = new ArraySL(["a", "b", "a"]);
        const mode = arr.mostFrequent();
        expect(mode.length).toBe(2);
        expect(mode.every((item) => item === "a")).toBe(true);
    });

    test("should return an empty array if there is no unique mode", () => {
        const arr = new ArraySL([1, 2, 3]);
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });

    test("should return an empty array if all items are modes", () => {
        const arr = new ArraySL([1, 1, 2, 2]);
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });

    test("should return multiple modes if they have the same frequency", () => {
        const arr = new ArraySL([1, 1, 2, 2, 3]);
        const result = arr.mostFrequent((i) => i);
        expect(result.sort()).toEqual([1, 1, 2, 2]);
    });

    test("should return an empty array for an empty array", () => {
        const arr = new ArraySL();
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });
});
