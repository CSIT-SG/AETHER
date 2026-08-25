import { BaseProps, buttonVariants } from '@/lib/ButtonProps';

interface ButtonProps extends BaseProps {
    onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
    type?: "button" | "submit" | "reset";
}

export default function Button({ 
    children, 
    variant = "primary", 
    type = "button",
    className,
    ...props 
}: ButtonProps) {
    const styles = "my-4 py-2 px-4 rounded inline-flex items-center";
    const variantStyles = buttonVariants[variant];

    return (
        <button 
        type={type}
        className={`${styles} ${variantStyles}`}
        {...props}
        >
            {children}
        </button>
    );
}
