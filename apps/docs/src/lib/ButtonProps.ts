import { ReactNode } from 'react';

export const buttonVariants = {
    primary: "bg-blue-500 text-white hover:bg-blue-600",
    secondary: "bg-gray-500 text-white hover:bg-gray-600",
    download: "bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold",
};

type Variant = keyof typeof buttonVariants

export interface BaseProps {
    children: ReactNode;
    variant?: Variant;
    className?: string;
}