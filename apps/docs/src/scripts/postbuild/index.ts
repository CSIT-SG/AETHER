import { generatePagefind } from "./pagefind";

async function main() {
    await generatePagefind();
}

main().catch((error) => {
    console.error("Error during postbuild:", error);
    process.exit(1);
});