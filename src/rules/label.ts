import { AbstractRule } from './base'
import { getOctokit } from '@actions/github'
import * as core from '@actions/core'
import { PullRequestContext } from 'src/context'

export class LabelRule extends AbstractRule {
  public static type: string = 'labeled'
  public label: string | string[]
  public userName: string | string[] | null
  public userTeam: string | string[] | null
  constructor(
    label: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
    this.label = label
    this.userName = userName ?? null
    this.userTeam = userTeam ?? null
  }

  public async check(context: PullRequestContext): Promise<boolean> {
    const { githubToken, githubContext } = context
    const octokit = getOctokit(githubToken)
    const { owner, repo } = githubContext.repo
    const { number } = githubContext.issue
    const allEvents = await octokit.rest.issues.listEvents({ owner, repo, issue_number: number })
    const labeledEvents = allEvents.data.filter((event) => event.event === 'labeled')
    core.info(`labeledEvents: ${JSON.stringify(labeledEvents)}`)
    return false
  }

  public static fromObject(obj: any): LabelRule {
    return new LabelRule(obj.label, obj['user-name'], obj['user-team'])
  }
}
