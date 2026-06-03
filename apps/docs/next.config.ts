import type { NextConfig } from "next";
import nextra from "nextra";

const nextConfig: NextConfig = {
	/* config options here */
	reactCompiler: true,
	output: 'standalone',
};

export default nextra({
	// nextra config here
})(nextConfig);
