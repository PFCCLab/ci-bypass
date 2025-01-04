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
    const isValidLabeledUserByName = async (
      currentEventUserName: string,
      allowUserNames: string[]
    ) => {
      const result = allowUserNames.includes(currentEventUserName)
      if (!result) {
        core.info(`user ${currentEventUserName} not in allowUserNames`)
      }
      return result
    }
    const isValidLabeledUserByTeam = async (
      currentEventUserName: string,
      allowUserTeams: string[]
    ) => {
      return await Promise.all(
        allowUserTeams.map(async (team) => {
          core.info(`Before get teamMembers ${team} in ${owner}`)
          try {
            const { data: teamMembers } = await octokit.rest.teams.listMembersInOrg({
              org: owner,
              team_slug: team,
            })
            core.info(`After get teamMembers ${team}`)
            return teamMembers.map((member) => member.login)
          } catch (error) {
            core.error(
              `Error in get teamMembers ${team} in ${owner}, check your token has org:read permission`
            )
            throw error
          }
        })
      ).then((results) => {
        const result = results.some((members) => members.includes(currentEventUserName))
        core.info(
          `user ${currentEventUserName} in allowUserTeams ${allowUserTeams} result ${result}`
        )
        if (!result) {
          core.info(`user ${currentEventUserName} not in allowUserTeams ${allowUserTeams}`)
        }
        return result
      })
    }
    const isValidLabel = async (label: string): Promise<Boolean> => {
      for (const labeledEvent of labeledEvents.reverse()) {
        if ('label' in labeledEvent && labeledEvent.label.name === label) {
          const currentEventUserName = labeledEvent.actor.login
          return (
            (await isValidLabeledUserByName(currentEventUserName, this.userNames)) ||
            (await isValidLabeledUserByTeam(currentEventUserName, this.userTeams))
          )
        }
      }
      core.error(`label ${label} not found in labeledEvents`)
      return false
    }
    core.info(`labeledEvents: ${JSON.stringify(labeledEvents)}`)
    core.info(`currentLabels: ${JSON.stringify(currentLabels)}`)
    return await Promise.all(currentLabels.map(isValidLabel)).then((results) =>
      results.some(Boolean)
    )
  }

  public static fromObject(obj: any): LabelRule {
    return new LabelRule(obj.label, obj['username'], obj['user-team'])
  }
}
