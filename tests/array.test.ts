import { test, expect } from "bun:test";
import { ArraySL } from "../src/array";

test("ArraySL getters should work correctly", () => {
    const arr = new ArraySL([1, 2, 3]);
    expect(arr.first).toBe(1);
    expect(arr.last).toBe(3);
    const randomElement = arr.random;
    expect(arr.includes(randomElement!)).toBe(true);
});

test("ArraySL unique method should return unique elements", () => {
    const arr = new ArraySL([{ id: 1 }, { id: 2 }, { id: 1 }]);
    const uniqueArr = arr.unique(item => item.id);
    expect(uniqueArr.length).toBe(2);
    expect(uniqueArr.map(i => i.id)).toEqual([1, 2]);
});

test("ArraySL median method should find the median", () => {
    const arr = new ArraySL([{ val: 10 }, { val: 20 }, { val: 5 }]);
    const median = arr.median(item => item.val);
    expect(median.length).toBe(1);
    expect(median[0]).toEqual({ val: 10 });

    const evenArr = new ArraySL([{ val: 10 }, { val: 20 }]);
    const medianEven = evenArr.median(item => item.val);
    expect(medianEven.length).toBe(2);
    expect(medianEven.map(i => i.val)).toEqual([10, 20]);
});

test("ArraySL mode method should find the mode", () => {
    const arr = new ArraySL([{ val: 'a' }, { val: 'b' }, { val: 'a' }]);
    const mode = arr.mode(item => item.val);
    expect(mode.length).toBe(2);
    expect(mode.every(item => item.val === 'a')).toBe(true);
});

test("ArraySL method chaining should be preserved", () => {
    const arr = new ArraySL([{ id: 1, group: 'a' }, { id: 2, group: 'b' }, { id: 3, group: 'a' }]);
    const result = arr.filter(item => item.group === 'a');
    expect(result instanceof ArraySL).toBe(true);
    expect(result.length).toBe(2);
    expect(result.first).toEqual({ id: 1, group: 'a' });
});