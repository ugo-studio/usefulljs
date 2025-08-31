import fs from "fs";
import path from "path";

const srcDir = path.resolve(process.cwd(), "src", "lib");
const packageJsonPath = path.resolve(process.cwd(), "package.json");

const files = fs.readdirSync(srcDir);
const utilityFiles = files.filter(
  (file) => file !== "index.ts" && file.endsWith(".ts")
);

const exports = {
  ".": {
    import: "./dist/esm/index.js",
    require: "./dist/cjs/index.js",
  },
};

for (const file of utilityFiles) {
  const utilityName = file.replace(".ts", "");
  exports[`./${utilityName}`] = {
    import: `./dist/esm/lib/${utilityName}.js`,
    require: `./dist/cjs/lib/${utilityName}.js`,
  };
}

const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
packageJson.exports = exports;

fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + "\n");

console.log("Successfully generated exports in package.json");
