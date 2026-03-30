/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // Custom color palette
                neutral: {
                    50: '#FBF5F3',   // Cream (lightest)
                    100: '#F5EBE7',  // Lighter cream
                    200: '#E8D5CE',  // Light cream with hint of warmth
                    300: '#C5B5AF',  // Medium light
                    400: '#8A7A74',  // Medium
                    500: '#5A4A44',  // Medium dark
                    600: '#3A2A24',  // Dark
                    700: '#1A0A14',  // Darker
                    800: '#0A0518',  // Very dark
                    900: '#000022',  // Navy black (darkest)
                },
                // Primary Action (Orange)
                primary: {
                    100: '#FEF4E8',  // Very light orange
                    200: '#F9D9A8',  // Light orange
                    300: '#F5C074',  // Medium light orange
                    400: '#ED9F3B',  // Medium orange
                    500: '#E28413',  // Brand orange
                    600: '#C77210',  // Darker orange
                    700: '#A05F0D',  // Dark orange
                    800: '#7A4A0A',  // Very dark orange
                    900: '#4D2F06',  // Darkest orange
                },
                // Semantic Colors
                success: {
                    100: '#e6f4ea',
                    600: '#2d6a4f',
                },
                warning: {
                    100: '#FEF4E8',
                    600: '#E28413',  // Using primary orange
                },
                error: {
                    100: '#fce8e6',
                    600: '#b71c1c',
                },
            },
            fontFamily: {
                sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
                mono: ['SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 'Droid Sans Mono', 'Source Code Pro', 'monospace'],
            },
        },
    },
    plugins: [],
}
