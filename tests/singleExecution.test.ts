import { describe, expect, mock, test } from "bun:test";

import { singleExecution } from "../src/singleExecution";

describe("singleExecution", () => {
    test("should only execute a task once with the same string key", async () => {
        const task = mock(() =>
            new Promise((resolve) => setTimeout(() => resolve("result"), 50))
        );
        const key = "unique-key";

        const [result1, result2] = await Promise.all([
            singleExecution(task, key),
            singleExecution(task, key),
        ]);

        expect(result1).toBe("result");
        expect(result2).toBe("result");
        expect(task).toHaveBeenCalledTimes(1);
    });

    test("should execute a task again after the first one completes", async () => {
        const task = mock(() =>
            new Promise((resolve) => setTimeout(() => resolve("result"), 50))
        );
        const key = "another-key";

        await singleExecution(task, key);
        await singleExecution(task, key);

        expect(task).toHaveBeenCalledTimes(2);
    });

    test("should handle different key types and values", async () => {
        const task = mock(() =>
            new Promise((resolve) => setTimeout(() => resolve("result"), 50))
        );

        // Object keys
        await Promise.all([
            singleExecution(task, { id: 1 }),
            singleExecution(task, { id: 1 }),
        ]);
        expect(task).toHaveBeenCalledTimes(1);

        await singleExecution(task, { id: 2 });
        expect(task).toHaveBeenCalledTimes(2);

        // Array keys
        await Promise.all([
            singleExecution(task, [1, 2, 3]),
            singleExecution(task, [1, 2, 3]),
        ]);
        expect(task).toHaveBeenCalledTimes(3);
    });

    test("should re-throw errors and clear the lock", async () => {
        const error = new Error("Task failed");
        const failingTask = mock(() =>
            new Promise((_, reject) => setTimeout(() => reject(error), 50))
        );
        const key = "failing-key";

        // First call should reject
        await expect(singleExecution(failingTask, key)).rejects.toThrow(
            "Task failed",
        );
        expect(failingTask).toHaveBeenCalledTimes(1);

        // Second call should re-execute and also reject
        await expect(singleExecution(failingTask, key)).rejects.toThrow(
            "Task failed",
        );
        expect(failingTask).toHaveBeenCalledTimes(2);
    });

    test("should deduplicate based on function source when no key is provided", async () => {
        const task = mock(() =>
            new Promise((resolve) => setTimeout(() => resolve("result"), 50))
        );

        // Define the function once
        const fetcher = () => singleExecution(task);

        const [result1, result2] = await Promise.all([fetcher(), fetcher()]);

        expect(result1).toBe("result");
        expect(result2).toBe("result");
        expect(task).toHaveBeenCalledTimes(1);

        // Calling again after completion should re-execute
        await fetcher();
        expect(task).toHaveBeenCalledTimes(2);
    });

    test("should differentiate between different functions when no key is provided", async () => {
        const task1 = mock(() => Promise.resolve(1));
        const task2 = mock(() => Promise.resolve(2));

        const result1 = await singleExecution(task1);
        const result2 = await singleExecution(task2);

        expect(result1).toBe(1);
        expect(result2).toBe(2);
        expect(task1).toHaveBeenCalledTimes(1);
        expect(task2).toHaveBeenCalledTimes(1);
    });

    test("should treat objects with different key orders as the same key", async () => {
        const task = mock(() =>
            new Promise((resolve) => setTimeout(() => resolve("result"), 50))
        );
        const key1 = { a: 1, b: 2 };
        const key2 = { b: 2, a: 1 };

        const [result1, result2] = await Promise.all([
            singleExecution(task, key1),
            singleExecution(task, key2),
        ]);

        expect(result1).toBe("result");
        expect(result2).toBe("result");
        expect(task).toHaveBeenCalledTimes(1);
    });
});
