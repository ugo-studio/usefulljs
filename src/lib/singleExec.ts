import { toCanonicalString } from "./object.js";

/**
 * A serializable value that can be used as a key. It can be a primitive,
 * a plain object, or an array that can be safely canonicalized.
 *
 * Note: Keys should be representable via `toCanonicalString`. For complex types,
 * consider providing your own POJO representation before passing as a key.
 */
export type SerializableKey = unknown;

/**
 * Options to configure a `SingleExecution` instance.
 */
export interface SingleExecutionOptions {
    /**
     * Optional scope or namespace to isolate keys across different instances.
     * If provided, it becomes part of the canonicalized key.
     */
    scope?: string;
}

/**
 * SingleFlight-style executor that deduplicates concurrent async work by key.
 *
 * This class implements a "promise memoization" pattern: concurrent calls with the
 * same key share the same in-flight Promise and will resolve/reject together.
 * Once the Promise settles (resolve or reject), it is removed from the cache,
 * so a subsequent call will start a fresh execution.
 *
 * Keying strategy:
 * - Keys are canonicalized via `toCanonicalString` to achieve value-based equality
 *   for objects/arrays and stable ordering suitable for Map keys
 *   (see stable JSON stringification references: [npmjs.com](https://www.npmjs.com/package/fast-json-stable-stringify),
 *   [mattiasmartens.github.io](https://mattiasmartens.github.io/big-m/canon.js.html)).
 * - If `key` is omitted, the function’s source (`taskFn.toString()`) is used.
 *
 * @example
 * const single = new SingleExecution({ scope: 'api' });
 *
 * // Deduplicate concurrent fetches for the same user
 * function fetchUser(userId: string) {
 *   return single.run(
 *     () => Promise.resolve({ id: userId }), // e.g., api.get(`/users/${userId}`)
 *     `user:${userId}`,
 *   );
 * }
 *
 * await Promise.all([fetchUser('1'), fetchUser('1')]); // Executes once
 */
export class SingleExecution {
    /**
     * In-flight promise cache keyed by a canonicalized string.
     */
    private readonly activeRequests = new Map<string, Promise<unknown>>();

    /**
     * Optional instance scope to isolate keys between instances.
     */
    private readonly scope?: string;

    /**
     * Create a new `SingleExecution` instance.
     *
     * @param {SingleExecutionOptions} [options] Optional configuration.
     */
    constructor(options: SingleExecutionOptions = {}) {
        this.scope = options.scope;
    }

    /**
     * Execute an async task ensuring only one concurrent execution per key.
     *
     * If a call with the same key is already in-flight, the existing Promise is returned.
     * Once the promise settles (resolved or rejected), it is removed from the cache to
     * avoid caching errors and to allow future retries.
     *
     * Notes:
     * - If `key` is omitted, the canonical form of `taskFn.toString()` is used. This may collide
     *   if distinct function instances have identical source strings.
     * - `key` may be any value that your `toCanonicalString` can represent deterministically.
     *   For complex instances, consider pre-converting to POJOs; see discussion on custom
     *   stringification [bscotch.net](https://www.bscotch.net/post/custom-stringification-javascript).
     *
     * @template TResult The result type of the asynchronous task.
     * @param {() => Promise<TResult>} taskFn The asynchronous function to execute.
     * @param {SerializableKey} [key] Optional unique key to identify the task.
     * @returns {Promise<TResult>} A Promise that resolves or rejects with the task result.
     */
    async run<TResult>(
        taskFn: () => Promise<TResult>,
        key?: SerializableKey,
    ): Promise<TResult> {
        // Prefer explicit key; otherwise fall back to function source string.
        const keySource = key !== undefined ? key : { fn: taskFn.toString() };
        const canonicalKey = this.serializeKey(keySource);

        const existingPromise = this.activeRequests.get(canonicalKey);
        if (existingPromise) {
            return existingPromise as Promise<TResult>;
        }

        // First caller for this key starts the task and stores the promise immediately.
        const newPromise = taskFn();
        this.activeRequests.set(canonicalKey, newPromise);

        try {
            return await newPromise;
        } finally {
            // Remove only if the stored promise is the same (avoid racing with a newer call).
            if (this.activeRequests.get(canonicalKey) === newPromise) {
                this.activeRequests.delete(canonicalKey);
            }
        }
    }

    /**
     * Current number of in-flight entries.
     */
    get size(): number {
        return this.activeRequests.size;
    }

    /**
     * Clear all in-flight entries (rarely needed; primarily for tests or shutdown).
     */
    clear(): void {
        this.activeRequests.clear();
    }

    /**
     * Compute a canonical string for a given key, including optional scope.
     *
     * @param {SerializableKey} keySource The raw key or function source wrapper.
     * @returns {string} A canonicalized key string.
     * @internal
     */
    private serializeKey(keySource: SerializableKey): string {
        return this.scope
            ? toCanonicalString({ scope: this.scope, key: keySource })
            : toCanonicalString(keySource);
    }
}

/**
 * A shared, application-level instance suitable for most use cases.
 * Use this if you don't need custom scoping or multiple isolated caches.
 */
export const singleExecutionService = new SingleExecution();

/**
 * Backward-compatible helper that delegates to the shared instance.
 *
 * @template TResult
 * @param {() => Promise<TResult>} taskFn The asynchronous function to execute.
 * @param {SerializableKey} [key] Optional unique key to identify the task.
 * @returns {Promise<TResult>} A Promise that resolves or rejects with the task result.
 *
 * @example
 * // Example 1: Basic deduplication with a string key
 * async function fetchUser(userId: string) {
 *   return singleExec(
 *     () => Promise.resolve({ id: userId }),
 *     `user-${userId}`,
 *   );
 * }
 *
 * // Example 2: Using an object as a key
 * async function searchProducts(filters: object) {
 *   return singleExec(
 *     () => Promise.resolve({
 *          // results
 *      }),
 *     filters,
 *   );
 * }
 *
 * // Example 3: No key provided (canonicalizes the function's source)
 * const fetchConfig = () => singleExec(() => Promise.resolve({}));
 * await Promise.all([fetchConfig(), fetchConfig()]); // executes `fetchConfig` once
 */
export function singleExec<TResult>(
    taskFn: () => Promise<TResult>,
    key?: SerializableKey,
): Promise<TResult> {
    return singleExecutionService.run(taskFn, key);
}
