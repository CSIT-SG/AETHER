import { BaseProps, buttonVariants } from "@/components/constants";
import { twMerge } from "tailwind-merge";

interface ButtonProps extends BaseProps {
	onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
	type?: "button" | "submit" | "reset";
}

export function Button({
	children,
	variant = "primary",
	type = "button",
	className,
	...props
}: ButtonProps) {
	const styles = "my-4 py-2 px-4 rounded inline-flex items-center";
	const variantStyles = buttonVariants[variant];

	return (
		<button type={type} className={twMerge(styles, variantStyles)} {...props}>
			{children}
		</button>
	);
}
