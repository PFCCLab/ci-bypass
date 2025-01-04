import * as core from '@actions/core'
import { wait } from './wait'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const skipIf: any = core.getInput('skip-if')
    core.info(`skip-if: ${skipIf}`)

    // Set outputs for other workflow steps to use
    core.setOutput('can-skip', true)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
