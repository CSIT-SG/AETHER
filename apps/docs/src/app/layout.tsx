import { Footer, Layout, Navbar } from "nextra-theme-docs";
import { Banner, Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import "nextra-theme-docs/style.css";

export const metadata = {
	// Define your metadata here
	// For more information on metadata API, see: https://nextjs.org/docs/app/building-your-application/optimizing/metadata
};

const navbar = (
	<Navbar
		logo={<b>Nextra</b>}
		// ... Your additional navbar options
	/>
);

export default async function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html
			lang="en"
			dir="ltr"
			// Suggested by `next-themes` package https://github.com/pacocoursey/next-themes#with-app
			suppressHydrationWarning
		>
			<body>
				<Layout
					navbar={navbar}
					pageMap={await getPageMap()}
					docsRepositoryBase="https://github.com/SebassNoob/AETHER-next"
				>
					{children}
				</Layout>
			</body>
		</html>
	);
}
