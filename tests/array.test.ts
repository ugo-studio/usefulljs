import { describe, expect, test } from "bun:test";

import { ArrayUF } from "../src/array";

describe("ArrayUF Constructor and Core", () => {
    test("should create an instance from an array", () => {
        const arr = new ArrayUF([1, 2, 3]);
        expect(arr).toBeInstanceOf(ArrayUF);
        expect(arr.length).toBe(3);
        expect(arr.first).toBe(1);
    });

    test("should create an empty instance", () => {
        const arr = new ArrayUF();
        expect(arr.length).toBe(0);
    });

    test("should create an instance with a specified length", () => {
        const arr = new ArrayUF(5);
        expect(arr.length).toBe(5);
    });

    test("method chaining should be preserved (Symbol.species)", () => {
        const arr = new ArrayUF([
            { id: 1, group: "a" },
            { id: 2, group: "b" },
            { id: 3, group: "a" },
        ]);
        const result = arr.filter((item) => item.group === "a");
        expect(result).toBeInstanceOf(ArrayUF);
        expect(result.length).toBe(2);
        expect(result.first?.id).toBe(1);
    });
});

describe("ArrayUF Getters", () => {
    test("getters should work on a non-empty array", () => {
        const arr = new ArrayUF([1, 2, 3, 4, 5]);
        expect(arr.first).toBe(1);
        expect(arr.last).toBe(5);
        const randomElement = arr.random;
        expect(arr.includes(randomElement!)).toBe(true);
        expect(arr.isEmpty).toBe(false);
        expect(arr.isNotEmpty).toBe(true);
    });

    test("getters should return undefined for an empty array", () => {
        const arr = new ArrayUF<number>();
        expect(arr.first).toBeUndefined();
        expect(arr.last).toBeUndefined();
        expect(arr.random).toBeUndefined();
        expect(arr.isEmpty).toBe(true);
        expect(arr.isNotEmpty).toBe(false);
    });
});

describe("ArrayUF.unique", () => {
    test("should return unique elements using default accessor", () => {
        const arr = new ArrayUF([1, 2, 2, 3, 1, 4]);
        const uniqueArr = arr.unique();
        expect(uniqueArr).toEqual(new ArrayUF([1, 2, 3, 4]));
    });

    test("should return unique elements using a custom accessor", () => {
        const arr = new ArrayUF([{ id: 1 }, { id: 2 }, { id: 1 }]);
        const uniqueArr = arr.unique({ accessor: (item) => item.id });
        expect(uniqueArr.length).toBe(2);
        expect(uniqueArr.map((i) => i.id)).toEqual([1, 2]);
    });

    test("should return an empty array if the original is empty", () => {
        const arr = new ArrayUF();
        expect(arr.unique()).toEqual(new ArrayUF());
    });

    test("should handle an array with no duplicates", () => {
        const arr = new ArrayUF([1, 2, 3]);
        expect(arr.unique()).toEqual(new ArrayUF([1, 2, 3]));
    });
});

describe("ArrayUF.duplicates", () => {
    const complexArr = new ArrayUF([
        { id: 1, val: "a" }, // 1
        { id: 2, val: "b" }, // 2
        { id: 1, val: "c" }, // 3
        { id: 3, val: "d" }, // 4
        { id: 1, val: "e" }, // 5
        { id: 2, val: "f" }, // 6
    ]);

    test("should return no duplicates for a unique array", () => {
        const arr = new ArrayUF([1, 2, 3]);
        expect(arr.duplicates().length).toBe(0);
    });

    test("should return an empty array for an empty array", () => {
        const arr = new ArrayUF();
        expect(arr.duplicates().length).toBe(0);
    });

    describe("mode: 'all'", () => {
        test("should get all occurrences of duplicated items", () => {
            const arr = new ArrayUF([1, 2, 1, 3, 1, 2]);
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
            const arr = new ArrayUF([1, 2, 1, 3, 1, 2]);
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
            const arr = new ArrayUF([1, 2, 1, 3, 1, 2]);
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

describe("ArrayUF.middle", () => {
    test("should find the single middle item in an odd-length array", () => {
        const arr = new ArrayUF([10, 20, 5, 30, 15]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArrayUF([5]));
    });

    test("should find the two middle items in an even-length array", () => {
        const evenArr = new ArrayUF([10, 20, 5, 30]);
        const middle = evenArr.middle();
        expect(middle).toEqual(new ArrayUF([20, 5]));
    });

    test("should return an empty array for an empty input array", () => {
        const arr = new ArrayUF([]);
        const middle = arr.middle();
        expect(middle.length).toBe(0);
    });

    test("should return the single item for an array with one element", () => {
        const arr = new ArrayUF([42]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArrayUF([42]));
    });

    test("should return both items for an array with two elements", () => {
        const arr = new ArrayUF([1, 2]);
        const middle = arr.middle();
        expect(middle).toEqual(new ArrayUF([1, 2]));
    });
});

describe("ArrayUF.mostFrequent", () => {
    test("should find the mode in a simple case", () => {
        const arr = new ArrayUF([{ val: "a" }, { val: "b" }, { val: "a" }]);
        const mode = arr.mostFrequent((item) => item.val);
        expect(mode.length).toBe(2);
        expect(mode.every((item) => item.val === "a")).toBe(true);
    });

    test("should find the mode with default accessor (item itself)", () => {
        const arr = new ArrayUF(["a", "b", "a"]);
        const mode = arr.mostFrequent();
        expect(mode.length).toBe(2);
        expect(mode.every((item) => item === "a")).toBe(true);
    });

    test("should return an empty array if there is no unique mode", () => {
        const arr = new ArrayUF([1, 2, 3]);
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });

    test("should return an empty array if all items are modes", () => {
        const arr = new ArrayUF([1, 1, 2, 2]);
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });

    test("should return multiple modes if they have the same frequency", () => {
        const arr = new ArrayUF([1, 1, 2, 2, 3]);
        const result = arr.mostFrequent((i) => i);
        expect(result.sort()).toEqual([1, 1, 2, 2]);
    });

    test("should return an empty array for an empty array", () => {
        const arr = new ArrayUF();
        expect(arr.mostFrequent((i) => i).length).toBe(0);
    });
});

describe("ArrayUF.groupBy", () => {
    test("should group elements by a given key", () => {
        const arr = new ArrayUF([
            { group: "a", value: 1 },
            { group: "b", value: 2 },
            { group: "a", value: 3 },
        ]);
        const grouped = arr.groupBy((item) => item.group);
        expect(Object.keys(grouped)).toEqual(["a", "b"]);
        expect(grouped["a"]).toBeInstanceOf(ArrayUF);
        expect(grouped["a"].length).toBe(2);
        expect(grouped["a"].map((i) => i.value)).toEqual([1, 3]);
        expect(grouped["b"].length).toBe(1);
        expect(grouped["b"].map((i) => i.value)).toEqual([2]);
    });

    test("should return an empty object for an empty array", () => {
        const arr = new ArrayUF([]);
        const grouped = arr.groupBy((item: any) => item.group);
        expect(grouped).toEqual({});
    });

    test("should work with number keys", () => {
        const arr = new ArrayUF([
            { group: 1, value: 1 },
            { group: 2, value: 2 },
            { group: 1, value: 3 },
        ]);
        const grouped = arr.groupBy((item) => item.group);
        expect(Object.keys(grouped)).toEqual(["1", "2"]);
        expect(grouped[1].length).toBe(2);
    });
});

describe("ArrayUF.chunk", () => {
    test("should split an array into chunks of a specified size", () => {
        const arr = new ArrayUF([1, 2, 3, 4, 5]);
        const chunks = arr.chunk(2);
        expect(chunks.length).toBe(3);
        expect(chunks[0]).toEqual(new ArrayUF([1, 2]));
        expect(chunks[1]).toEqual(new ArrayUF([3, 4]));
        expect(chunks[2]).toEqual(new ArrayUF([5]));
        expect(chunks[0]).toBeInstanceOf(ArrayUF);
    });

    test("should handle arrays that divide evenly", () => {
        const arr = new ArrayUF([1, 2, 3, 4]);
        const chunks = arr.chunk(2);
        expect(chunks.length).toBe(2);
        expect(chunks[0]).toEqual(new ArrayUF([1, 2]));
        expect(chunks[1]).toEqual(new ArrayUF([3, 4]));
    });

    test("should return an empty array for an empty input array", () => {
        const arr = new ArrayUF([]);
        const chunks = arr.chunk(2);
        expect(chunks.length).toBe(0);
    });

    test("should return an empty array for a chunk size of 0 or less", () => {
        const arr = new ArrayUF([1, 2, 3]);
        expect(arr.chunk(0).length).toBe(0);
        expect(arr.chunk(-1).length).toBe(0);
    });

    test("should handle a chunk size larger than the array length", () => {
        const arr = new ArrayUF([1, 2, 3]);
        const chunks = arr.chunk(5);
        expect(chunks.length).toBe(1);
        expect(chunks[0]).toEqual(new ArrayUF([1, 2, 3]));
    });
});

describe("ArrayUF.shuffle", () => {
    test("should return a new array with the same elements", () => {
        const arr = new ArrayUF([1, 2, 3, 4, 5]);
        const shuffled = arr.shuffle();
        expect(shuffled.length).toBe(arr.length);
        expect(shuffled.sort()).toEqual(arr.sort());
    });

    test("should not modify the original array", () => {
        const original = new ArrayUF([1, 2, 3]);
        original.shuffle();
        expect(original).toEqual(new ArrayUF([1, 2, 3]));
    });

    test("should return a new ArrayUF instance", () => {
        const arr = new ArrayUF([1, 2, 3]);
        const shuffled = arr.shuffle();
        expect(shuffled).toBeInstanceOf(ArrayUF);
    });

    test("should handle an empty array", () => {
        const arr = new ArrayUF([]);
        const shuffled = arr.shuffle();
        expect(shuffled.length).toBe(0);
    });
});

describe("ArrayUF.compact", () => {
    test("should remove all falsy values", () => {
        const arr = new ArrayUF([0, 1, false, 2, "", 3, null, "a", undefined, NaN]);
        const compacted = arr.compact();
        expect(compacted).toEqual(new ArrayUF([1, 2, 3, "a"]));
    });

    test("should return an empty array if all values are falsy", () => {
        const arr = new ArrayUF([0, false, "", null, undefined, NaN]);
        const compacted = arr.compact();
        expect(compacted.length).toBe(0);
    });

    test("should return an equivalent array if no values are falsy", () => {
        const arr = new ArrayUF([1, "hello", true, {}]);
        const compacted = arr.compact();
        expect(compacted.length).toBe(4);
        expect(compacted).toEqual(arr);
    });

    test("should handle an empty array", () => {
        const arr = new ArrayUF([]);
        const compacted = arr.compact();
        expect(compacted.length).toBe(0);
    });
});