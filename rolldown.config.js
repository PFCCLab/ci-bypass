import { defineConfig } from 'rolldown'
import { nodeExternals } from 'rollup-plugin-node-externals'

export default defineConfig({
  input: 'src/index.ts',
  output: {
    file: 'dist/index.js',
  },
  plugins: [nodeExternals()],
})
