import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",

    // The ML layer's Python virtual environment.
    //
    // Not ours to lint: scikit-learn ships a little JavaScript for rendering
    // estimator diagrams in notebooks, and ESLint walks into ml/.venv and
    // reports warnings about it. Those warnings are noise in every local run
    // and would be noise in CI too, since `npm run ml:setup` creates the same
    // directory there. Nothing under .venv is written by this project — it is
    // rebuilt from ml/requirements.txt — so there is nothing here to check.
    "ml/.venv/**",
  ]),
]);

export default eslintConfig;
