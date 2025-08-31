import { describe, expect, mock, test } from "bun:test";

import { retry } from "../src/lib/retry";

describe("retry", () => {
    test("should succeed on the first attempt without retrying", async () => {
        const task = mock(async () => "Success");
        const result = await retry(task);
        expect(result).toBe("Success");
        expect(task).toHaveBeenCalledTimes(1);
    });

    test("should eventually succeed after a few failed attempts", async () => {
        let attempts = 0;
        const task = mock(async () => {
            attempts++;
            if (attempts < 3) { // Fails on the first two attempts
                throw new Error("Failed");
            }
            return "Success";
        });

        const result = await retry(task, {
            limit: 3,
            backoff: { initialDelay: 10 },
        });
        expect(result).toBe("Success");
        expect(task).toHaveBeenCalledTimes(3);
    });

    test("should fail after exhausting all retry attempts", async () => {
        const task = mock(async () => {
            throw new Error("Persistent Failure");
        });

        const promise = retry(task, {
            limit: 2,
            backoff: { initialDelay: 10 },
        });
        await expect(promise).rejects.toThrow("Persistent Failure");
        expect(task).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
    });

    test("should call onRetry callback for each retry attempt", async () => {
        const onRetry = mock(() => {});
        const task = mock(async () => {
            throw new Error("Failed");
        });

        const limit = 3;
        await expect(
            retry(task, { limit, backoff: { initialDelay: 10 }, onRetry }),
        ).rejects
            .toThrow();

        expect(onRetry).toHaveBeenCalledTimes(limit);
        // Check arguments for the first call
        expect(onRetry.mock.calls[0][0]).toBeInstanceOf(Error); // error
        expect(onRetry.mock.calls[0][1]).toBe(1); // attempt
        expect(onRetry.mock.calls[0][2]).toBe(10); // delay
        // Check arguments for the second call (exponential backoff)
        expect(onRetry.mock.calls[1][2]).toBe(20); // delay = 10 * 2^1
    });

    test("should respect the maxDelay cap", async () => {
        const onRetry = mock(() => {});
        const task = mock(async () => {
            throw new Error("Failed");
        });

        await expect(
            retry(task, {
                limit: 4,
                backoff: { initialDelay: 50, maxDelay: 120 },
                onRetry,
            }),
        ).rejects.toThrow();

        expect(onRetry).toHaveBeenCalledTimes(4);
        expect(onRetry.mock.calls[0][2]).toBe(50); // 50 * 2^0 = 50
        expect(onRetry.mock.calls[1][2]).toBe(100); // 50 * 2^1 = 100
        expect(onRetry.mock.calls[2][2]).toBe(120); // 50 * 2^2 = 200, capped at 120
        expect(onRetry.mock.calls[3][2]).toBe(120); // 50 * 2^3 = 400, capped at 120
    });

    test("should not delay if initialDelay is 0", async () => {
        const task = mock(async () => {
            throw new Error("Failed");
        });
        const onRetry = mock(() => {});

        const startTime = Date.now();
        await expect(
            retry(task, { limit: 2, backoff: { initialDelay: 0 }, onRetry }),
        )
            .rejects.toThrow();
        const endTime = Date.now();

        expect(onRetry).toHaveBeenCalledTimes(2);
        expect(onRetry.mock.calls[0][2]).toBe(0); // No delay
        expect(endTime - startTime).toBeLessThan(50); // Should be very fast
    });

    test("should not retry if limit is 0", async () => {
        const task = mock(async () => {
            throw new Error("Failed");
        });

        await expect(retry(task, { limit: 0 })).rejects.toThrow("Failed");
        expect(task).toHaveBeenCalledTimes(1);
    });
});
