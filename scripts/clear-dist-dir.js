import fs from "fs";
import path from "path";

const distDir = path.resolve(process.cwd(), "dist");

await fs.promises.rm(distDir, { recursive: true, force: true });
await fs.promises.mkdir(distDir, { recursive: true });

console.log("Successfully cleared dist directory");
