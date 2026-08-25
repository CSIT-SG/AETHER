import { BaseProps, buttonVariants } from "@/components/constants";
import { twMerge } from "tailwind-merge";

interface LinkButton extends BaseProps {
	href: string;
	download?: string;
	target?: string;
	rel?: string;
}

export function LinkButton({
	children,
	variant = "primary",
	className,
	href,
	download,
	...props
}: LinkButton) {
	const styles = "my-4 py-2 px-4 rounded inline-flex items-center";
	const variantStyles = buttonVariants[variant];

	return (
		<a href={href} download={download} className={twMerge(styles, variantStyles)} {...props}>
			{children}
		</a>
	);
}
