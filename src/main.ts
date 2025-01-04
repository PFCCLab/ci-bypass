import * as core from '@actions/core'
import { context as githubContext } from '@actions/github'
import { resolveCompositeAsync } from './composite'
import { ByPassCheckerBuilder, LabelRule } from './rules'

function parseArrayInput(input: string, separator: string): string[] {
  return input.split(separator).map((item) => item.trim())
}

function parseRuleRawObjectFromInput(): any {
  const type = core.getInput('type')
  switch (type) {
    case LabelRule.type:
      return {
        type: LabelRule.type,
        label: parseArrayInput(core.getInput('label'), '|'),
        username: parseArrayInput(core.getInput('username'), '|'),
        'user-team': parseArrayInput(core.getInput('user-team'), '|'),
      }
    case 'composite':
      return JSON.parse(core.getInput('composite-rules'))
    default:
      throw new Error(`Invalid rule type: ${type}`)
  }
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const githubToken: string = core.getInput('github-token')
    const rawRule = parseRuleRawObjectFromInput()
    core.info(`rawRule: ${JSON.stringify(rawRule)}`)

    async function check(value: any): Promise<boolean> {
      const bypassChecker = new ByPassCheckerBuilder().use(LabelRule).build()
      return bypassChecker.check(value, { githubToken, githubContext })
    }

    const result = await resolveCompositeAsync(check)(rawRule)
    core.info(`check result: ${result}`)
    // Set outputs for other workflow steps to use
    core.setOutput('can-skip', result)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
