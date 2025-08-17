// --- Default Configuration Constants ---
const DEFAULT_LIMIT = 2;
const DEFAULT_INITIAL_DELAY = 0;
const DEFAULT_MAX_DELAY = Infinity;

/**
 * Configuration options for the retryTask function.
 */
export interface RetryOptions<TResult> {
    /**
     * The maximum number of retry attempts to make after the initial failure.
     * For example, a limit of 2 means the task will be executed a total of 3 times
     * (the initial attempt + 2 retries).
     * @default 2
     */
    limit?: number;

    /**
     * The initial delay in milliseconds before the first retry attempt.
     * Set to a value greater than 0 to enable a delay. Subsequent retries
     * will use an exponential backoff strategy (delay doubles with each attempt).
     * @default 0
     */
    initialDelay?: number;

    /**
     * The maximum delay in milliseconds allowed between retries. This puts a cap
     * on the exponential backoff, preventing excessively long wait times.
     * Use `Infinity` for no upper limit.
     * @default Infinity
     */
    maxDelay?: number;

    /**
     * An optional callback function that is executed before each retry attempt.
     * It receives the error that caused the failure, the upcoming attempt number,
     * and the calculated delay. This is useful for logging or side effects.
     * If this callback throws an error, it will be logged but will not stop the
     * retry process.
     *
     * @param error The error that triggered the retry.
     * @param attempt The number of the upcoming retry attempt (e.g., 1 for the first retry).
     * @param delay The delay in milliseconds before the next attempt.
     */
    onRetry?: (error: unknown, attempt: number, delay: number) => void;
}

/**
 * Executes an asynchronous task and automatically retries it if it fails.
 * By default, retries happen immediately without any delay. An exponential
 * backoff delay can be enabled by setting the `initialDelay` option.
 *
 * This function is useful for handling transient errors in network requests or
 * other operations that might succeed on a subsequent attempt.
 *
 * @template TResult The expected result type of the asynchronous task.
 * @param {() => Promise<TResult>} taskFn The asynchronous function to execute.
 *   This function should not take any arguments and must return a Promise.
 * @param {RetryOptions<TResult>} [options={}] Optional configuration to control
 *   the retry behavior, such as the number of retries and delay timings.
 * @returns {Promise<TResult>} A promise that either resolves with the task's
 *   successful result or rejects with the last error encountered after all
 *   attempts have been exhausted.
 * @example
 * ```ts
 * // Example 1: Basic usage with default settings (2 retries, no delay)
 * const data = await retryTask(fetchData);
 *
 * // Example 2: Customizing retry behavior to include a delay
 * const user = await retryTask(fetchUser, {
 *   limit: 3,
 *   initialDelay: 100, // Enable a 100ms initial delay with backoff
 *   onRetry: (error, attempt) => {
 *     console.log(`Attempt ${attempt} failed. Retrying in a moment...`, error);
 *   }
 * });
 * ```
 */
export async function retry<TResult>(
    taskFn: () => Promise<TResult>,
    options: RetryOptions<TResult> = {},
): Promise<TResult> {
    const {
        limit = DEFAULT_LIMIT,
        initialDelay = DEFAULT_INITIAL_DELAY,
        maxDelay = DEFAULT_MAX_DELAY,
        onRetry,
    } = options;

    let lastError: unknown;

    for (let attempt = 0; attempt <= limit; attempt++) {
        try {
            return await taskFn();
        } catch (error) {
            lastError = error;

            if (attempt === limit) {
                break;
            }

            const exponentialDelay = initialDelay * Math.pow(2, attempt);
            const delay = Math.min(exponentialDelay, maxDelay);

            if (typeof onRetry === "function") {
                try {
                    onRetry(error, attempt + 1, delay);
                } catch (onRetryError) {
                    console.error(
                        "Error within onRetry callback:",
                        onRetryError,
                    );
                }
            }

            // Only introduce a delay if it's greater than 0.
            if (delay > 0) {
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    throw lastError;
}
