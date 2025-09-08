import { createCanonicalString } from "../utils.js";

/**
 * Converts any JavaScript value to a deterministic, canonical string representation.
 * This is useful for comparing objects and other values in a consistent way.
 * @param value The value to convert.
 * @returns The canonical string representation of the value.
 */
export function toCanonicalString(value: any): string {
    return createCanonicalString(value);
}

/**
 * Checks if all the given values are equal by comparing their canonical string representations.
 * @param values The values to compare.
 * @returns `true` if all the values are equal, `false` otherwise.
 */
export function areEqual(...values: any[]): boolean {
    let previousCanonicalString: string | null = null;
    for (const value of values) {
        const canonicalString = createCanonicalString(value);
        if (previousCanonicalString === null) {
            previousCanonicalString = canonicalString;
            continue;
        }
        if (previousCanonicalString !== canonicalString) {
            return false;
        }
    }
    return true;
}

/**
 * Checks if any of the given values are not equal by comparing their canonical string representations.
 * @param values The values to compare.
 * @returns `true` if any of the values are not equal, `false` otherwise.
 */
export function areNotEqual(...values: any[]): boolean {
    return !areEqual(...values);
}

/**
 * Retrieves the value at a specified path of an object.
 * @param obj The object to query.
 * @param path The path of the property to retrieve (e.g., 'a.b[0].c').
 * @returns The value at the path, or `undefined` if the path does not exist.
 */
export function getValue(obj: any, path: string | string[]): any {
    const pathArray = Array.isArray(path)
        ? path
        : path.replace(/\[(\d+)\]/g, ".$1").split(".").filter((key) => key);
    let current = obj;
    for (let i = 0; i < pathArray.length; i++) {
        if (current === null || current === undefined) {
            return undefined;
        }
        current = current[pathArray[i]];
    }
    return current;
}

/**
 * Creates an object composed of the picked object properties.
 * @template T The type of the source object.
 * @template K The type of the keys to pick.
 * @param obj The source object.
 * @param keys The properties to pick.
 * @returns The new object with picked properties.
 */
export function pick<T extends object, K extends keyof T>(
    obj: T,
    keys: K[],
): Pick<T, K> {
    const result = {} as Pick<T, K>;
    const keySet = new Set(keys);
    for (const key of Object.keys(obj)) {
        if (keySet.has(key as K)) {
            result[key as K] = obj[key as K];
        }
    }
    return result;
}

/**
 * Creates an object with properties from the source object that are not omitted.
 * @template T The type of the source object.
 * @template K The type of the keys to omit.
 * @param obj The source object.
 * @param keys The properties to omit.
 * @returns The new object without the omitted properties.
 */
export function omit<T extends object, K extends keyof T>(
    obj: T,
    keys: K[],
): Omit<T, K> {
    const result = { ...obj };
    for (const key of keys) {
        delete result[key];
    }
    return result;
}
