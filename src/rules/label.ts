import { AbstractRule } from './base'
import { getOctokit } from '@actions/github'
import * as core from '@actions/core'
import { PullRequestContext } from 'src/context'

function resolveOneOrMoreOption<T>(value: T | T[]): T[] {
  return Array.isArray(value) ? value : [value]
}

function resolveMaybeOneOrMoreOption<T>(value: T | T[] | undefined): T[] {
  return value ? resolveOneOrMoreOption(value) : []
}

export class LabelRule extends AbstractRule {
  public static type: string = 'labeled'
  public labels: string[]
  public userNames: string[]
  public userTeams: string[]
  constructor(
    label: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
    this.labels = resolveOneOrMoreOption(label)
    this.userNames = resolveMaybeOneOrMoreOption(userName)
    this.userTeams = resolveMaybeOneOrMoreOption(userTeam)
  }

  public async check(context: PullRequestContext): Promise<boolean> {
    const { githubToken, githubContext } = context
    const octokit = getOctokit(githubToken)
    const { owner, repo } = githubContext.repo
    const { number } = githubContext.issue
    const allEventsResponse = await octokit.rest.issues.listEvents({
      owner,
      repo,
      issue_number: number,
    })
    const allLabelsResponse = await octokit.rest.issues.listLabelsOnIssue({
      owner,
      repo,
      issue_number: number,
    })
    const currentLabels = allLabelsResponse.data
      .map((label) => label.name)
      .filter((label) => this.labels.includes(label))

    const labeledEvents = allEventsResponse.data.filter((event) => event.event === 'labeled')
    core.info(`labeledEvents: ${JSON.stringify(labeledEvents)}`)
    core.info(`currentLabels: ${JSON.stringify(currentLabels)}`)
    return false
  }

  public static fromObject(obj: any): LabelRule {
    return new LabelRule(obj.label, obj['user-name'], obj['user-team'])
  }
}
