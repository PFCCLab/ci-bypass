import { defineConfig } from 'vite'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { nodeExternals } from 'rollup-plugin-node-externals'

const dir = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  build: {
    lib: {
      fileName: 'index',
      entry: resolve(dir, './src/index.ts'),
      formats: ['es'],
    },
  },
  plugins: [nodeExternals()],
})
