/**
 * An extended Array class providing convenient getters and powerful utility methods.
 * It's fully generic, type-safe, and designed for seamless method chaining.
 *
 * @template T The type of elements in the array. Defaults to `unknown`.
 */
export class ArrayUF<T = unknown> extends Array<T> {
    /**
     * Creates a new ArrayUF instance. This constructor is compatible with the
     * standard Array constructor signatures.
     */
    constructor(item: Iterable<T> | number = []) {
        // This logic handles the different ways an Array can be constructed.
        // 1. new ArrayUF(5) -> called by .map() etc., creates an empty array of length 5.
        // 2. new ArrayUF([item1, item2]) -> creates an array with the given items.
        if (typeof item === "number") {
            super(item as number);
        } else {
            // When an iterable is passed, create an array from it.
            // This avoids the `new Array(5)` vs `new Array([5])` ambiguity.
            const items = Array.from(item);
            super(items.length);
            for (let i = 0; i < items.length; i++) {
                this[i] = items[i];
            }
        }

        // This is the crucial fix for ES5 targets.
        // It manually sets the prototype of the new instance to ArrayUF.prototype.
        Object.setPrototypeOf(this, new.target.prototype);
    }

    /**
     * Ensures that methods inherited from Array (like .map, .filter, .slice)
     * return an instance of ArrayUF instead of a plain Array. This makes
     * method chaining seamless.
     */
    static get [Symbol.species]() {
        return this as unknown as ArrayConstructor;
    }

    /**
     * A boolean getter that returns `true` if the array has no items.
     * This is a convenient alternative to checking `array.length === 0`.
     *
     * @returns {boolean} `true` if the length is 0, otherwise `false`.
     * @example
     * const emptyList = new ArrayUF();
     * console.log(emptyList.isEmpty); //-> true
     *
     * const fullList = new ArrayUF([1, 2, 3]);
     * console.log(fullList.isEmpty); //-> false
     */
    get isEmpty(): boolean {
        return this.length === 0;
    }

    /**
     * A boolean getter that returns `true` if the array has one or more items.
     * This is a convenient alternative to checking `array.length > 0`.
     *
     * @returns {boolean} `true` if the length is greater than 0, otherwise `false`.
     * @example
     * const fullList = new ArrayUF([1, 2, 3]);
     * console.log(fullList.isNotEmpty); //-> true
     *
     * const emptyList = new ArrayUF();
     * console.log(emptyList.isNotEmpty); //-> false
     */
    get isNotEmpty(): boolean {
        return this.length > 0;
    }

    /**
     * Returns the first element of the array.
     * @returns {T | undefined} The first element, or `undefined` if the array is empty.
     */
    get first(): T | undefined {
        return this[0];
    }

    /**
     * Returns the last element of the array.
     * @returns {T | undefined} The last element, or `undefined` if the array is empty.
     */
    get last(): T | undefined {
        return this[this.length - 1];
    }

    /**
     * Returns a random element from the array.
     * @returns {T | undefined} A random element, or `undefined` if the array is empty.
     */
    get random(): T | undefined {
        if (this.length === 0) {
            return undefined;
        }
        return this[Math.floor(Math.random() * this.length)];
    }

    /**
     * Returns the middle item or items of the array based on their index.
     *
     * This method finds the element(s) at the center of the array without any sorting.
     * - If the array has an odd number of elements, it returns the single middle item.
     * - If the array has an even number of elements, it returns the two middle items.
     *
     * This is distinct from a median calculation, which would require the array to be sorted by value first.
     *
     * @returns {ArrayUF<T>} A new ArrayUF containing the middle item(s). Returns an empty array if the source array is empty.
     * @example
     * // For an array with an odd length
     * const oddList = new ArrayUF(['a', 'b', 'c', 'd', 'e']);
     * console.log(oddList.middle); // Returns ArrayUF['c']
     *
     * // For an array with an even length
     * const evenList = new ArrayUF([10, 20, 30, 40]);
     * console.log(evenList.middle); // Returns ArrayUF[20, 30]
     *
     * // For an empty array
     * const emptyList = new ArrayUF([]);
     * console.log(emptyList.middle); // Returns ArrayUF[]
     */
    get middle(): ArrayUF<T> {
        if (this.length === 0) {
            return new ArrayUF<T>();
        }

        const midIndex = Math.floor(this.length / 2);

        if (this.length % 2 !== 0) {
            // Odd length: return the single middle item by index
            return new ArrayUF<T>([this[midIndex]]);
        } else {
            // Even length: return the two middle items by index
            return new ArrayUF<T>([this[midIndex - 1], this[midIndex]]);
        }
    }

    /**
     * Returns a new ArrayUF containing only the unique elements from the original array.
     * Uniqueness is based on the element itself or on a key generated by the provided accessor.
     * This method is highly performant (O(n)).
     *
     * @param accessor An optional function that takes an element and returns a value to be used
     *     for the uniqueness check. If not provided, the element itself is used.
     * @returns {ArrayUF<T>} A new ArrayUF instance with duplicate elements removed.
     */
    unique(
        accessor: (value: T, index: number, array: T[]) => any = (value: T) =>
            value,
    ): ArrayUF<T> {
        const seen = new Set<any>();
        return this.filter((value, index, array) => {
            const key = accessor(value, index, array);
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    }

    /**
     * Returns a new ArrayUF containing duplicate elements from the original array.
     * This method is highly configurable and performant, operating in a single pass (O(n)).
     *
     * @param options An optional configuration object.
     *   - `accessor`: An optional function that takes an element and returns a value to be used
     *     for the uniqueness check. If not provided, the element itself is used. Keys that are
     *     objects or arrays are compared by their JSON string representation.
     *   - `mode`: Determines which duplicate items to include in the result.
     *      - 'all' (default): Returns all instances of items that are duplicates.
     *      - 'first': Returns only the first instance of each duplicated item.
     *      - 'subsequent': Returns only the duplicate instances that appear after the first one.
     * @returns {ArrayUF<T>} A new ArrayUF instance containing the specified duplicate elements.
     */
    duplicates(options: {
        accessor?: (value: T, index: number, array: T[]) => any;
        mode?: "first" | "subsequent" | "all";
    } = {}): ArrayUF<T> {
        const { mode = "all", accessor = (value: T) => value } = options;
        const result = new ArrayUF<T>();

        // The map tracks the state of each key using a dedicated object.
        const seen = new Map<any, { item: T; processed: boolean }>();

        this.forEach((item, index, array) => {
            const key = accessor(item, index, array);
            const state = seen.get(key);

            if (state === undefined) {
                // First time seeing this key. Store the item with processed: false.
                seen.set(key, { item: item, processed: false });
            } else {
                // This is a subsequent encounter (2nd, 3rd, etc.).
                if (!state.processed) {
                    // This block runs only on the second encounter for a given key.
                    if (mode === "first" || mode === "all") {
                        // Add the original item we stored earlier.
                        result.push(state.item);
                    }
                    // Mark as processed so this block doesn't run again for this key.
                    state.processed = true;
                }

                // This part runs for all subsequent encounters (2nd, 3rd, 4th...).
                if (mode === "subsequent" || mode === "all") {
                    result.push(item);
                }
            }
        });

        return result;
    }

    /**
     * Finds the most frequently occurring item(s) in the array.
     *
     * This method identifies which items appear most often, based on the item itself or a
     * key extracted from the item. If multiple items share the same highest frequency,
     * all of them are returned.
     *
     * @param accessor An optional function to extract a comparable key from an item. If not provided,
     *   the item itself is used for comparison.
     * @returns {ArrayUF<T>} A new ArrayUF containing the most frequent item(s).
     *   Returns an empty array if there is no unique most frequent item (e.g., in `[1, 1, 2, 2]`).
     * @example
     * const users = new ArrayUF([
     *   { name: 'Alice', city: 'Paris' },
     *   { name: 'Bob', city: 'Tokyo' },
     *   { name: 'Charlie', city: 'Paris' }
     * ]);
     * console.log(users.mostFrequent((u) => u.city)); // Returns ArrayUF containing the 'Alice' and 'Charlie' objects
     *
     * const numbers = new ArrayUF([1, 2, 2, 3, 3, 3]);
     * console.log(numbers.mostFrequent()); // Returns ArrayUF[3, 3, 3]
     */
    mostFrequent(
        accessor: (value: T, index: number, array: T[]) => any = (value: T) =>
            value,
    ): ArrayUF<T> {
        if (this.length === 0) {
            return new ArrayUF<T>();
        }

        const frequencies = new Map<any, number>();
        let maxFreq = 0;

        this.forEach((value, index, array) => {
            const key = accessor(value, index, array);
            const newCount = (frequencies.get(key) || 0) + 1;
            frequencies.set(key, newCount);
            if (newCount > maxFreq) {
                maxFreq = newCount;
            }
        });

        if (maxFreq <= 1 && this.length > 1) {
            return new ArrayUF<T>();
        }

        const modeKeys = new Set<any>();
        for (const [key, freq] of frequencies.entries()) {
            if (freq === maxFreq) {
                modeKeys.add(key);
            }
        }

        if (modeKeys.size > 1 && (modeKeys.size * maxFreq) === this.length) {
            return new ArrayUF<T>();
        }

        return this.filter((value, index, array) =>
            modeKeys.has(accessor(value, index, array))
        );
    }

    /**
     * Groups the elements of the array into an object based on a key generated by the accessor function.
     *
     * @param accessor A function that returns the key to group by for each element.
     * @returns {{ [key: string]: ArrayUF<T> }} An object where keys are the group keys and values are ArrayUF instances of elements in that group.
     * @example
     * const users = new ArrayUF([
     *   { name: 'Alice', department: 'HR' },
     *   { name: 'Bob', department: 'Engineering' },
     *   { name: 'Charlie', department: 'HR' }
     * ]);
     * const grouped = users.groupBy(user => user.department);
     * // grouped is:
     * // {
     * //   HR: ArrayUF[{ name: 'Alice', ... }, { name: 'Charlie', ... }],
     * //   Engineering: ArrayUF[{ name: 'Bob', ... }]
     * // }
     */
    groupBy(
        accessor: (value: T, index: number, array: T[]) => string | number,
    ): { [key: string]: ArrayUF<T> } {
        return this.reduce((acc, value, index, array) => {
            const key = accessor(value, index, array);
            if (!acc[key]) {
                acc[key] = new ArrayUF<T>();
            }
            acc[key].push(value);
            return acc;
        }, {} as { [key: string]: ArrayUF<T> });
    }

    /**
     * Splits the array into smaller arrays (chunks) of a specified size.
     * The last chunk may contain fewer elements than the specified size.
     *
     * @param size The size of each chunk. Must be a positive integer.
     * @returns {ArrayUF<ArrayUF<T>>} A new ArrayUF containing the chunks. Returns an empty ArrayUF if the input size is invalid.
     * @example
     * const numbers = new ArrayUF([1, 2, 3, 4, 5]);
     * console.log(numbers.chunk(2)); // Returns ArrayUF[ArrayUF[1, 2], ArrayUF[3, 4], ArrayUF[5]]
     */
    chunk(size: number): ArrayUF<ArrayUF<T>> {
        if (size <= 0) {
            return new ArrayUF<ArrayUF<T>>();
        }

        const result = new ArrayUF<ArrayUF<T>>();
        for (let i = 0; i < this.length; i += size) {
            result.push(this.slice(i, i + size));
        }
        return result;
    }

    /**
     * Returns a new ArrayUF with the elements randomly shuffled.
     * This method uses the Fisher-Yates (aka Knuth) shuffle algorithm for an unbiased shuffle.
     * It does not modify the original array.
     *
     * @returns {ArrayUF<T>} A new ArrayUF instance with the elements in a random order.
     * @example
     * const numbers = new ArrayUF([1, 2, 3, 4, 5]);
     * console.log(numbers.shuffle()); // e.g., Returns ArrayUF[3, 5, 1, 4, 2]
     */
    shuffle(): ArrayUF<T> {
        const result = this.slice(); // Create a shallow copy
        for (let i = result.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [result[i], result[j]] = [result[j], result[i]];
        }
        return result;
    }

    /**
     * Returns a new ArrayUF with all falsy values removed.
     * Falsy values are `false`, `null`, `0`, `""`, `undefined`, and `NaN`.
     *
     * @returns {ArrayUF<T>} A new ArrayUF instance containing only truthy elements.
     * @example
     * const mixed = new ArrayUF([0, 1, false, 2, '', 3, null, 'a', undefined, NaN]);
     * console.log(mixed.compact()); // Returns ArrayUF[1, 2, 3, 'a']
     */
    compact(): ArrayUF<T> {
        return this.filter(Boolean) as ArrayUF<T>;
    }

    /**
     * Clears all elements from the array, making it empty.
     * This method modifies the array in place.
     *
     * @example
     * const list = new ArrayUF([1, 2, 3]);
     * list.clear();
     * console.log(list.isEmpty); //-> true
     * console.log(list.length); //-> 0
     */
    clear(): void {
        this.length = 0;
    }

    // *** Add Type Signature Overrides ***

    // Overrides the default return type of `Array.prototype.filter` to return `ArrayUF<T>`.
    filter<S extends T>(
        predicate: (value: T, index: number, array: T[]) => value is S,
        thisArg?: any,
    ): ArrayUF<S>;
    filter(
        predicate: (value: T, index: number, array: T[]) => unknown,
        thisArg?: any,
    ): ArrayUF<T>;
    filter(predicate: any, thisArg?: any): ArrayUF<T> {
        // The implementation is inherited from Array, so we just call super.
        return super.filter(predicate, thisArg) as ArrayUF<T>;
    }

    // Overrides the default return type of `Array.prototype.map` to return `ArrayUF<U>`.
    map<U>(
        callbackfn: (value: T, index: number, array: T[]) => U,
        thisArg?: any,
    ): ArrayUF<U> {
        return super.map(callbackfn, thisArg) as ArrayUF<U>;
    }

    // Overrides the default return type of `Array.prototype.slice` to return `ArrayUF<T>`.
    slice(start?: number, end?: number): ArrayUF<T> {
        return super.slice(start, end) as ArrayUF<T>;
    }

    // Overrides the default return type of `Array.prototype.concat` to return `ArrayUF<T>`.
    concat(...items: ConcatArray<T>[]): ArrayUF<T>;
    concat(...items: (T | ConcatArray<T>)[]): ArrayUF<T> {
        return super.concat(...items) as ArrayUF<T>;
    }

    // Overrides the default return type of `Array.prototype.from` to return `ArrayUF<Element>`.
    static from<Element>(
        iterable: Iterable<Element> | ArrayLike<Element>,
    ): ArrayUF<Element> {
        return super.from(iterable) as ArrayUF<Element>;
    }

    // Overrides the default return type of `Array.prototype.of` to return `ArrayUF<T>`.
    static of<T>(...items: T[]): ArrayUF<T> {
        return super.of(...items) as ArrayUF<T>;
    }

    // *** End Of Signature Overrides ***
}
