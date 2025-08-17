/**
 * A serializable value that can be used as a key. It can be a primitive,
 * a plain object, or an array that can be safely stringified with JSON.
 */
type SerializableKey = unknown;

/**
 * Creates a SHA-256 hash of the given data. This is a robust way to generate a
 * consistent key from complex data types like objects or arrays.
 * @param data The data to hash.
 * @returns A promise that resolves to the hex-encoded hash string.
 * @internal
 */
async function getHash(data: SerializableKey): Promise<string> {
    let dataString: string;
    // Ensure consistent string representation for hashing.
    if (typeof data === "string") {
        dataString = data;
    } else if (data !== null && typeof data === "object") {
        // Handles arrays and plain objects. May throw on circular references.
        dataString = JSON.stringify(data);
    } else {
        // Handles primitives like number, boolean, null, undefined.
        dataString = String(data);
    }

    const encoder = new TextEncoder();
    const encodedData = encoder.encode(dataString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encodedData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // Convert each byte to a 2-character hex string.
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * A map to store promises of currently active (in-flight) tasks.
 * The key is a unique hash, and the value is the promise returned by the task.
 */
const activeRequests = new Map<string, Promise<unknown>>();

/**
 * Ensures that an asynchronous task is only executed once at a time for a given key.
 *
 * If this function is called while a task with the same key is already running,
 * it will return the promise of the existing task instead of starting a new one.
 * This is useful for preventing duplicate network requests or other expensive
 * operations. Once a task is complete (either resolves or rejects), its promise is
 * removed, and the next call with the same key will trigger a new execution.
 *
 * @template TResult The expected result type of the asynchronous task.
 * @param {() => Promise<TResult>} taskFn The asynchronous function to execute.
 * @param {SerializableKey} [key] An optional unique identifier for the task.
 *   If it's an object or array, it will be JSON-stringified and hashed.
 *   If not provided, the task function's source code (`taskFn.toString()`) is
 *   hashed to generate a key. Note that this may not be unique for different
 *   function instances with identical source code.
 * @returns {Promise<TResult>} A promise that resolves or rejects with the result of the task.
 * @example
 * ```ts
 * // Example 1: Basic deduplication with a string key
 * async function fetchUser(userId: string) {
 *   // This function will only be executed once, even if called multiple times in parallel.
 *   return ensureSingleExecution(
 *     () => {
 *       console.log(`Fetching user ${userId}...`);
 *       return api.fetch(`/users/${userId}`);
 *     },
 *     `user-${userId}` // A simple, descriptive key
 *   );
 * }
 *
 * Promise.all([fetchUser('123'), fetchUser('123')]); // "Fetching user 123..." is logged only once.
 *
 * // Example 2: Using an object as a key
 * async function searchProducts(filters: object) {
 *   return ensureSingleExecution(
 *     () => api.post('/products/search', filters),
 *     filters // The filters object is hashed to create a unique key
 *   );
 * }
 *
 * // Example 3: No key provided (hashes the function's source)
 * const fetchConfig = () => ensureSingleExecution(() => api.fetch('/config'));
 * Promise.all([fetchConfig(), fetchConfig()]); // The config is fetched only once.
 * ```
 */
export async function ensureSingleExecution<TResult>(
    taskFn: () => Promise<TResult>,
    key?: SerializableKey,
): Promise<TResult> {
    // If a key is provided, use it; otherwise, use the function's string representation.
    const keySource = key !== undefined ? key : taskFn.toString();
    const hashedKey = await getHash(keySource);

    const existingPromise = activeRequests.get(hashedKey);

    // If a request with the same key is already pending, return its promise.
    if (existingPromise) {
        return existingPromise as Promise<TResult>;
    }

    // --- This is the first call for this key ---

    // Create the promise and store it in the map immediately to handle race conditions.
    const newPromise = taskFn();
    activeRequests.set(hashedKey, newPromise);

    try {
        // Await the task's completion.
        return await newPromise;
    } finally {
        // IMPORTANT: Once the promise settles (resolves or rejects), immediately
        // remove it from the map. This ensures the next call re-executes the task.
        // We check if the promise in the map is still the one we created,
        // preventing a race condition where a new task started before this one finished.
        if (activeRequests.get(hashedKey) === newPromise) {
            activeRequests.delete(hashedKey);
        }
    }
}
