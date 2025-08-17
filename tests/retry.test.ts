import { test, expect, mock } from "bun:test";
import { retry } from "../src/retry";

test("retry should eventually succeed", async () => {
    let attempts = 0;
    const task = mock(async () => {
        attempts++;
        if (attempts < 2) {
            throw new Error("Failed");
        }
        return "Success";
    });

    const result = await retry(task, { limit: 2, initialDelay: 10 });
    expect(result).toBe("Success");
    expect(task).toHaveBeenCalledTimes(2);
});

test("retry should fail after exhausting all attempts", async () => {
    const task = mock(async () => {
        throw new Error("Failed");
    });

    await expect(retry(task, { limit: 2, initialDelay: 10 })).rejects.toThrow("Failed");
    expect(task).toHaveBeenCalledTimes(3);
});

test("retry should call onRetry callback", async () => {
    const onRetry = mock(() => {});
    const task = mock(async () => {
        throw new Error("Failed");
    });

    await expect(retry(task, { limit: 2, initialDelay: 10, onRetry })).rejects.toThrow("Failed");
    expect(onRetry).toHaveBeenCalledTimes(2);
});