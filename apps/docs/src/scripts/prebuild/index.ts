import { generateGriffe } from "./griffe";


async function main(): Promise<void> {
    await generateGriffe();
}

main().catch((error) => {
    console.error("Error during prebuild:", error);
    process.exit(1);
});