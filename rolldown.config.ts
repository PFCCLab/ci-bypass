import { defineConfig, RolldownPlugin } from 'rolldown'
import { minify } from 'rollup-plugin-esbuild'

export default defineConfig({
  input: 'src/index.ts',
  output: {
    file: 'dist/index.js',
  },
  platform: 'node',
  plugins: [minify() as RolldownPlugin],
})
