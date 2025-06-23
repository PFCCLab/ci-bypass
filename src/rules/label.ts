import { getOctokit } from '@actions/github'
import * as core from '@actions/core'
import { AbstractRule } from './base.js'
import { PullRequestContext } from '../context.js'
import {
  resolveMaybeOneOrMoreOption,
  resolveOneOrMoreOption,
  isValidUser,
  withAllPages,
} from './utils.js'

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
    const allEventsResponse = await withAllPages(
      octokit,
      octokit.rest.issues.listEvents
    )({
      owner,
      repo,
      issue_number: number,
    })
    const allLabelsResponse = await withAllPages(
      octokit,
      octokit.rest.issues.listLabelsOnIssue
    )({
      owner,
      repo,
      issue_number: number,
    })
    const currentLabels = allLabelsResponse
      .map((label) => label.name)
      .filter((label) => this.labels.includes(label))

    const labeledEvents = allEventsResponse.filter((event) => event.event === 'labeled')

    const isValidLabel = async (label: string): Promise<Boolean> => {
      for (const labeledEvent of labeledEvents.reverse()) {
        if ('label' in labeledEvent && labeledEvent.label.name === label) {
          const currentEventUserName = labeledEvent.actor.login
          return await isValidUser(
            githubContext,
            octokit,
            currentEventUserName,
            this.userNames,
            this.userTeams
          )
        }
      }
      core.error(`label ${label} not found in labeledEvents`)
      return false
    }
    core.debug(`labeledEvents: ${JSON.stringify(labeledEvents)}`)
    core.debug(`currentLabels: ${JSON.stringify(currentLabels)}`)
    return await Promise.all(currentLabels.map(isValidLabel)).then((results) =>
      results.some(Boolean)
    )
  }

  public static fromObject(obj: any): LabelRule {
    return new LabelRule(obj.label, obj['username'], obj['user-team'])
  }
}
