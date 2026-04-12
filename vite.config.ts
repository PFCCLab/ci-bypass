import { defineConfig } from 'vite-plus'

export default defineConfig({
  test: {
    include: ['__tests__/**/*.test.ts'],
  },
  lint: {
    ignorePatterns: ['dist/**'],
    options: {
      typeAware: true,
      typeCheck: true,
    },
  },
  fmt: {
    printWidth: 100,
    tabWidth: 2,
    singleQuote: true,
    trailingComma: 'es5',
    semi: false,
    arrowParens: 'always',
    sortPackageJson: false,
    ignorePatterns: ['dist/', 'node_modules/', 'coverage/', 'pnpm-lock.yaml'],
  },
  pack: {
    deps: {
      alwaysBundle: [/^@actions\//],
      onlyBundle: false,
    },
    entry: ['src/index.ts'],
    platform: 'node',
    target: 'node24',
    outDir: 'dist',
    format: 'esm',
    fixedExtension: false,
    minify: true,
    sourcemap: false,
    dts: false,
  },
})
