import type { NextConfig } from "next";
import nextra from "nextra";

const nextConfig: NextConfig = {
	reactCompiler: true,
	output: 'standalone',
};

export default nextra({})(nextConfig);
