import { generatePagefind } from "./pagefind";
import { stageStandalone } from "./standalone";

async function main() {
	await generatePagefind();
	stageStandalone();
}

main().catch((error) => {
	console.error("Error during postbuild:", error);
	process.exit(1);
});
