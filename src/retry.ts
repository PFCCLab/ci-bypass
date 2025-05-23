import * as core from '@actions/core'
import { setTimeout as sleep } from 'timers/promises'

export function retryNTimes<T extends (...args: any[]) => Promise<any>>(fn: T, n: number) {
  return async (...args: Parameters<T>): Promise<Awaited<ReturnType<T>>> => {
    for (let i = 0; i < n; i++) {
      try {
        return await fn(...args)
      } catch (error) {
        core.warning(
          `Attempt ${i + 1} failed: ${error instanceof Error ? error.message : error}. Retrying...`
        )
        if (i < n - 1) {
          await sleep(1000 * 2 ** i) // Wait for 2**i seconds before retrying
        }
      }
    }
    throw new Error(`All ${n} attempts failed`)
  }
}
