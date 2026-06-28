/**
 * Système de design NexKeyLock — jetons exposés à Tailwind.
 *
 * Les couleurs pointent vers des variables CSS (définies dans `src/theme/`),
 * ce qui permet la bascule clair/sombre sans dupliquer les classes : on change
 * l'attribut `data-theme` sur <html> et toutes les couleurs suivent.
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="sombre"]'],
  theme: {
    extend: {
      colors: {
        fond: "rgb(var(--c-fond) / <alpha-value>)",
        surface: "rgb(var(--c-surface) / <alpha-value>)",
        "surface-haute": "rgb(var(--c-surface-haute) / <alpha-value>)",
        bordure: "rgb(var(--c-bordure) / <alpha-value>)",
        texte: "rgb(var(--c-texte) / <alpha-value>)",
        "texte-doux": "rgb(var(--c-texte-doux) / <alpha-value>)",
        accent: "rgb(var(--c-accent) / <alpha-value>)",
        "accent-contraste": "rgb(var(--c-accent-contraste) / <alpha-value>)",
        succes: "rgb(var(--c-succes) / <alpha-value>)",
        alerte: "rgb(var(--c-alerte) / <alpha-value>)",
        danger: "rgb(var(--c-danger) / <alpha-value>)",
      },
      borderRadius: {
        jeton: "0.625rem",
      },
      boxShadow: {
        panneau: "0 1px 2px rgb(0 0 0 / 0.06), 0 8px 24px rgb(0 0 0 / 0.08)",
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
