import { describe, expect, mock, test } from "bun:test";

import { singleExec, SingleExecution } from "../src/lib/singleExec";

function deferred<T>() {
    let resolve!: (value: T | PromiseLike<T>) => void;
    let reject!: (reason?: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

describe("singleExecution (shared instance helper)", () => {
    test("should only execute a task once with the same string key", async () => {
        const task = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("result"), 10)
                ),
        );
        const key = "unique-key";

        const [result1, result2] = await Promise.all([
            singleExec(task, key),
            singleExec(task, key),
        ]);

        expect(result1).toBe("result");
        expect(result2).toBe("result");
        expect(task).toHaveBeenCalledTimes(1);
    });

    test("should execute a task again after the first one completes", async () => {
        const task = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("result"), 10)
                ),
        );
        const key = "another-key";

        await singleExec(task, key);
        await singleExec(task, key);

        expect(task).toHaveBeenCalledTimes(2);
    });

    test("should handle different key types and values", async () => {
        const task = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("result"), 10)
                ),
        );

        // Object keys with same value
        await Promise.all([
            singleExec(task, { id: 1 }),
            singleExec(task, { id: 1 }),
        ]);
        expect(task).toHaveBeenCalledTimes(1);

        // Different object value
        await singleExec(task, { id: 2 });
        expect(task).toHaveBeenCalledTimes(2);

        // Array keys
        await Promise.all([
            singleExec(task, [1, 2, 3]),
            singleExec(task, [1, 2, 3]),
        ]);
        expect(task).toHaveBeenCalledTimes(3);
    });

    test("should re-throw errors and clear the lock", async () => {
        const error = new Error("Task failed");
        const failingTask = mock(
            () =>
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(error), 10)
                ),
        );
        const key = "failing-key";

        // First call should reject
        await expect(singleExec(failingTask, key)).rejects.toThrow(
            "Task failed",
        );
        expect(failingTask).toHaveBeenCalledTimes(1);

        // Second call should re-execute and also reject
        await expect(singleExec(failingTask, key)).rejects.toThrow(
            "Task failed",
        );
        expect(failingTask).toHaveBeenCalledTimes(2);
    });

    test("should deduplicate based on function source when no key is provided", async () => {
        const task = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("result"), 10)
                ),
        );

        const fetcher = () => singleExec(task);

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

        const result1 = await singleExec(task1);
        const result2 = await singleExec(task2);

        expect(result1).toBe(1);
        expect(result2).toBe(2);
        expect(task1).toHaveBeenCalledTimes(1);
        expect(task2).toHaveBeenCalledTimes(1);
    });

    test("should treat objects with different key orders as the same key", async () => {
        const task = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("result"), 10)
                ),
        );
        const key1 = { a: 1, b: 2 };
        const key2 = { b: 2, a: 1 };

        const [result1, result2] = await Promise.all([
            singleExec(task, key1),
            singleExec(task, key2),
        ]);

        expect(result1).toBe("result");
        expect(result2).toBe("result");
        expect(task).toHaveBeenCalledTimes(1);
    });
});

describe("SingleExecution (class instance)", () => {
    test("isolates in-flight cache per instance", async () => {
        const a = new SingleExecution();
        const b = new SingleExecution();

        const taskA = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("A"), 10)
                ),
        );
        const taskB = mock(
            () =>
                new Promise<string>((resolve) =>
                    setTimeout(() => resolve("B"), 10)
                ),
        );

        // Same key, different instances -> both should execute
        const [ra, rb] = await Promise.all([
            a.run(taskA, "k"),
            b.run(taskB, "k"),
        ]);
        expect(ra).toBe("A");
        expect(rb).toBe("B");
        expect(taskA).toHaveBeenCalledTimes(1);
        expect(taskB).toHaveBeenCalledTimes(1);

        // Within the same instance, concurrent calls dedupe
        const [r1, r2] = await Promise.all([
            a.run(taskA, "k"),
            a.run(taskA, "k"),
        ]);
        expect(r1).toBe("A");
        expect(r2).toBe("A");
        expect(taskA).toHaveBeenCalledTimes(2); // first call above + one more for these two
    });

    test("size reflects in-flight entries and is cleared after settle", async () => {
        const single = new SingleExecution();
        const d = deferred<string>();
        const task = mock(() => d.promise);

        const p = single.run(task, "key");
        expect(single.size).toBe(1);

        d.resolve("done");
        await p;

        expect(single.size).toBe(0);
        expect(task).toHaveBeenCalledTimes(1);
    });

    test("clear() empties in-flight map without affecting settled behavior", async () => {
        const single = new SingleExecution();
        const d = deferred<string>();
        const task = mock(() => d.promise);

        const p = single.run(task, "key");
        expect(single.size).toBe(1);

        single.clear();
        expect(single.size).toBe(0);

        // Resolve the old promise; subsequent calls should start fresh
        d.resolve("ok");
        await p;

        await single.run(task, "key");
        expect(task).toHaveBeenCalledTimes(2);
    });

    test("canonicalizes object keys irrespective of property order", async () => {
        const single = new SingleExecution();
        const task = mock(() => Promise.resolve("ok"));

        const [r1, r2] = await Promise.all([
            single.run(task, { x: 1, y: 2 }),
            single.run(task, { y: 2, x: 1 }),
        ]);

        expect(r1).toBe("ok");
        expect(r2).toBe("ok");
        expect(task).toHaveBeenCalledTimes(1);
    });
});
