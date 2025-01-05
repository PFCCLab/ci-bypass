import * as core from '@actions/core'
import { getOctokit, context as githubContext } from '@actions/github'

export function resolveOneOrMoreOption<T>(value: T | T[]): T[] {
  return Array.isArray(value) ? value : [value]
}

export function resolveMaybeOneOrMoreOption<T>(value: T | T[] | undefined): T[] {
  return value ? resolveOneOrMoreOption(value) : []
}

export async function isValidUserByName(
  currentEventUserName: string,
  allowUserNames: string[]
): Promise<boolean> {
  if (allowUserNames.length === 0) {
    return true
  }
  const result = allowUserNames.includes(currentEventUserName)
  if (!result) {
    core.info(
      `User ${currentEventUserName} has not enough permission to bypass the action (not in ${allowUserNames})`
    )
  }
  return result
}

export async function isValidUserByTeam(
  context: typeof githubContext,
  octokit: ReturnType<typeof getOctokit>,
  currentEventUserName: string,
  allowUserTeams: string[]
): Promise<boolean> {
  const owner = context.repo.owner
  if (allowUserTeams.length === 0) {
    return true
  }
  return await Promise.all(
    allowUserTeams.map(async (team) => {
      try {
        const { data: teamMembers } = await octokit.rest.teams.listMembersInOrg({
          org: owner,
          team_slug: team,
        })
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
    if (!result) {
      core.info(
        `User ${currentEventUserName} has not enough permission to bypass the action (not in ${allowUserTeams})`
      )
    }
    return result
  })
}
