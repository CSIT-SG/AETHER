import type { NextConfig } from "next";
import nextra from "nextra";

const nextConfig: NextConfig = {
	reactCompiler: true,
	output: 'standalone',
	async redirects() {
		return [
			{
				source: "/development/chatbot/worker-manager",
				destination: "/development/gui/worker-manager",
				permanent: true,
			},
			{
				source: "/development/chatbot/mcp-client",
				destination: "/development/gui/mcp-client",
				permanent: true,
			},
			{
				source: "/development/chatbot/styled-component",
				destination: "/development/gui/writing-gui-components",
				permanent: true,
			},
		];
	},
};

export default nextra({})(nextConfig);
