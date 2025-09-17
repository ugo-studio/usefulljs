function isTypedArray(obj: object) {
    const hasLength = "length" in obj && typeof obj.length === "number" &&
        obj.length >= 0;
    const hasJoin = "join" in obj && typeof obj.join === "function";
    const hasForEach = "forEach" in obj && typeof obj.forEach === "function";
    return hasLength && hasJoin && hasForEach;
}

/**
 * Creates a deterministic, canonical string representation of any JavaScript value.
 * This is used internally by `hashObject` to ensure consistent hashing.
 *
 * @param value The value to stringify.
 * @param visited A set to track visited objects and handle circular references.
 * @returns A canonical string representation of the value.
 */
export const createCanonicalString = (
    value: any,
    visited = new Set<any>(),
): string => {
    // Handle primitives and special values
    if (value === null) return "null";
    if (typeof value === "undefined") return '"[Undefined]"';
    if (typeof value === "bigint") return `"[BigInt]:${value.toString()}"`;
    if (typeof value === "symbol") return `"[Symbol]:${value.toString()}"`;
    if (typeof value === "function") return `"[Function]:${value.toString()}"`;
    if (typeof value !== "object") {
        // Handles string, number, boolean. JSON.stringify escapes strings correctly.
        return JSON.stringify(value);
    }

    // Handle circular references
    if (visited.has(value)) {
        return '"[Circular Reference]"';
    }
    visited.add(value);

    let result: string;

    try {
        // Handle specific object types
        if (value instanceof Date) {
            result = `"[Date]:${value.toISOString()}"`;
        } else if (value instanceof RegExp) {
            result = `"[RegExp]:${value.toString()}"`;
        } else if (value instanceof Map) {
            const mapEntries = Array.from(value.entries());
            // Sort map entries by canonical key string to ensure order
            mapEntries.sort((a, b) => {
                const keyA = createCanonicalString(a[0], new Set(visited));
                const keyB = createCanonicalString(b[0], new Set(visited));
                return keyA.localeCompare(keyB);
            });
            const stringifiedEntries = mapEntries.map(
                ([k, v]) =>
                    `${createCanonicalString(k, new Set(visited))}:${
                        createCanonicalString(
                            v,
                            new Set(visited),
                        )
                    }`,
            );
            result = `[Map]:{${stringifiedEntries.join(",")}}`;
        } else if (value instanceof Set) {
            const setValues = Array.from(value);
            // Sort set values by their canonical string to ensure order
            const stringifiedValues = setValues
                .map((v) => createCanonicalString(v, new Set(visited)))
                .sort();
            result = `[Set]:[${stringifiedValues.join(",")}]`;
        } else if (Array.isArray(value)) {
            const arrayItems = value.map((item) =>
                createCanonicalString(item, new Set(visited))
            );
            result = `[${arrayItems.join(",")}]`;
        } else if (value instanceof DataView) {
            const array = new Uint8Array(value.buffer);
            result = `[DataView]:[${array.join(",")}]`;
        } else if (value instanceof ArrayBuffer) {
            const array = new Uint8Array(value);
            result = `[ArrayBuffer]:[${array.join(",")}]`;
        } else if (isTypedArray(value) && value.constructor) {
            const name = value.constructor.name;
            result = `[${name}]:[${value.join(",")}]`;
        } else {
            // Handle plain objects
            const sortedKeys = Object.keys(value).sort();
            const objectPairs = sortedKeys.map((key) => {
                const stringifiedKey = JSON.stringify(key);
                const stringifiedValue = createCanonicalString(
                    value[key],
                    new Set(visited),
                );
                return `${stringifiedKey}:${stringifiedValue}`;
            });
            result = `{${objectPairs.join(",")}}`;
        }
    } finally {
        // After processing, remove the object from the visited set for the current path.
        // This allows the same object to be correctly processed if it appears in different branches of the data structure.
        visited.delete(value);
    }

    return result;
};
