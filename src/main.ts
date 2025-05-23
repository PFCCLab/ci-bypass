import * as core from '@actions/core'
import { context as githubContext } from '@actions/github'
import { resolveCompositeAsync } from './composite.js'
import { ByPassCheckerBuilder, LabelRule, CommentRule, ApproveRule } from './rules/index.js'

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
    case CommentRule.type:
      return {
        type: CommentRule.type,
        'comment-pattern': parseArrayInput(core.getInput('comment-pattern'), '|'),
        username: parseArrayInput(core.getInput('username'), '|'),
        'user-team': parseArrayInput(core.getInput('user-team'), '|'),
      }
    case ApproveRule.type:
      return {
        type: ApproveRule.type,
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
      default:
        throw new Error(`Invalid non-pull-request event strategy: ${nonPullRequestEventStrategy}`)
    }
  }
  return false
}

function retryNTimes<T>(fn: () => Promise<T>, n: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const attempt = (count: number) => {
      fn()
        .then(resolve)
        .catch((error) => {
          if (count < n) {
            core.warning(`Attempt ${count + 1} failed: ${error.message}. Retrying...`)
            // Wait for 2**count second before retrying
            setTimeout(() => attempt(count + 1), 1000 * 2 ** count)
          } else {
            reject(new Error(`All ${n} attempts failed`))
          }
        })
    }
    attempt(0)
  })
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    core.info('Starting the action...')
    if (checkNonPullRequestEvent()) {
      core.info('Non-pull-request event, skipping the check')
      return
    }
    const githubToken: string = core.getInput('github-token')
    const rawRule = parseRuleRawObjectFromInput()
    core.debug(`rawRule: ${JSON.stringify(rawRule)}`)

    async function check(value: any): Promise<boolean> {
      const bypassChecker = new ByPassCheckerBuilder()
        .use(LabelRule)
        .use(CommentRule)
        .use(ApproveRule)
        .build()
      return bypassChecker.check(value, { githubToken, githubContext })
    }

    const result = await retryNTimes(() => resolveCompositeAsync(check)(rawRule), 3)
    core.info(`Setting can-skip output to ${result}`)
    // Set outputs for other workflow steps to use
    core.setOutput('can-skip', result)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
