import { test, expect, mock } from "bun:test";
import { ensureSingleExecution } from "../src/ensureSingleExecution";

test("ensureSingleExecution should only execute a task once with the same key", async () => {
    const task = mock(() => new Promise(resolve => setTimeout(() => resolve("result"), 50)));
    const key = "unique-key";

    const [result1, result2] = await Promise.all([
        ensureSingleExecution(task, key),
        ensureSingleExecution(task, key),
    ]);

    expect(result1).toBe("result");
    expect(result2).toBe("result");
    expect(task).toHaveBeenCalledTimes(1);
});

test("ensureSingleExecution should execute a task again after the first one completes", async () => {
    const task = mock(() => new Promise(resolve => setTimeout(() => resolve("result"), 50)));
    const key = "another-key";

    await ensureSingleExecution(task, key);
    await ensureSingleExecution(task, key);

    expect(task).toHaveBeenCalledTimes(2);
});

test("ensureSingleExecution should handle different key types", async () => {
    const task = mock(() => new Promise(resolve => setTimeout(() => resolve("result"), 50)));
    const objectKey = { id: 1 };
    const arrayKey = [1, 2, 3];

    await Promise.all([
        ensureSingleExecution(task, objectKey),
        ensureSingleExecution(task, objectKey),
    ]);

    expect(task).toHaveBeenCalledTimes(1);

    await Promise.all([
        ensureSingleExecution(task, arrayKey),
        ensureSingleExecution(task, arrayKey),
    ]);

    expect(task).toHaveBeenCalledTimes(2);
});

test("ensureSingleExecution should re-throw errors", async () => {
    const error = new Error("Task failed");
    const failingTask = mock(() => new Promise((_, reject) => setTimeout(() => reject(error), 50)));
    const key = "failing-key";

    await expect(ensureSingleExecution(failingTask, key)).rejects.toThrow("Task failed");
});