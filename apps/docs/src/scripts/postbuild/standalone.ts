import { cpSync, existsSync } from "node:fs";

const STANDALONE_DIR = ".next/standalone";

export function stageStandalone(): void {
	if (!existsSync(STANDALONE_DIR)) {
		throw new Error(
			`${STANDALONE_DIR} not found. Ensure \`output: "standalone"\` is set and \`next build\` has run.`,
		);
	}

	cpSync(".next/static", `${STANDALONE_DIR}/.next/static`, { recursive: true });
	cpSync("public", `${STANDALONE_DIR}/public`, { recursive: true });
}
