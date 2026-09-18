import { spawn } from "node:child_process";

const SITE_DIR = ".next/server/app";
const OUTPUT_DIR = "public/_pagefind";

export async function generatePagefind(): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const child = spawn("pagefind", ["--site", SITE_DIR, "--output-path", OUTPUT_DIR], {
			stdio: "inherit",
			shell: process.platform === "win32",
		});

		child.once("error", reject);
		child.once("exit", (code) => {
			if (code === 0) {
				resolve();
				return;
			}

			reject(new Error(`pagefind exited with code ${code ?? "unknown"}.`));
		});
	});
}
