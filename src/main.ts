import * as core from '@actions/core'
import { resolveCompositeAsync } from './composite'
import { checkRule } from './rules'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const skipIf: any = JSON.parse(core.getInput('skip-if'))
    core.info(`skip-if: ${skipIf}`)

    async function check(value: any): Promise<boolean> {
      const context = {}
      return checkRule(value, context)
    }

    const result = await resolveCompositeAsync(check)(skipIf)
    core.info(`check result: ${result}`)
    // Set outputs for other workflow steps to use
    core.setOutput('can-skip', result)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
