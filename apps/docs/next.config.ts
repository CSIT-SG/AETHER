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
			// The chatbot section then moved under gui. Keep this last so the
			// three entries above still win.
			{
				source: "/development/chatbot/:path*",
				destination: "/development/gui/chatbot/:path*",
				permanent: true,
			},
		];
	},
};

export default nextra({})(nextConfig);
