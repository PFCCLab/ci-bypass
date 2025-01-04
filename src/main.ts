import * as core from '@actions/core'
import { context as githubContext } from '@actions/github'
import { resolveCompositeAsync } from './composite.js'
import { ByPassCheckerBuilder, LabelRule } from './rules/index.js'

const ALLOWED_NON_PULL_REQUEST_EVENT_STRATEGIES = [
  'always-skipped',
  'never-skipped',
  'always-failed',
]

const PULL_REQUEST_EVENTS = [
  'pull_request',
  'pull_request_target',
  'pull_request_review',
  'pull_request_review_comment',
]

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
      return JSON.parse(core.getInput('composite-rule'))
    default:
      throw new Error(`Invalid rule type: ${type}`)
  }
}

function checkNonPullRequestEvent() {
  const nonPullRequestEventStrategy = core.getInput('non-pull-request-event-strategy')
  core.debug(
    `Checking non-pull-request event strategy: ${nonPullRequestEventStrategy}, eventName: ${githubContext.eventName}`
  )
  if (!PULL_REQUEST_EVENTS.includes(githubContext.eventName)) {
    core.debug('This is not a pull_request related event')
    switch (nonPullRequestEventStrategy) {
      case 'always-skipped':
        core.setOutput('can-skip', true)
        return true
      case 'never-skipped':
        core.setOutput('can-skip', false)
        return true
      case 'always-failed':
        throw new Error('This action only supports pull_request related events')
    }
  }
  return false
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    if (checkNonPullRequestEvent()) return
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
