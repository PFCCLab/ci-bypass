import * as core from '@actions/core'
import { getOctokit, context as githubContext } from '@actions/github'

export function resolveOneOrMoreOption<T>(value: T | T[]): T[] {
  return Array.isArray(value) ? value : [value]
}

export function resolveMaybeOneOrMoreOption<T>(value: T | T[] | undefined): T[] {
  return value ? resolveOneOrMoreOption(value) : []
}

async function isValidUserByName(
  currentEventUserName: string,
  allowUserNames: string[]
): Promise<boolean> {
  const result = allowUserNames.includes(currentEventUserName)
  if (result) {
    core.info(`User ${currentEventUserName} has enough permission to bypass the action`)
  } else {
    core.info(
      `User ${currentEventUserName} has not enough permission to bypass the action (not in ${allowUserNames})`
    )
  }
  return result
}

async function isValidUserByTeam(
  context: typeof githubContext,
  octokit: ReturnType<typeof getOctokit>,
  currentEventUserName: string,
  allowUserTeams: string[]
): Promise<boolean> {
  const owner = context.repo.owner
  return await Promise.all(
    allowUserTeams.map(async (team) => {
      try {
        const teamMembers = (
          await withAllPages(
            octokit,
            octokit.rest.teams.listMembersInOrg
          )({
            org: owner,
            team_slug: team,
          })
        )
          .map((rawData) => rawData.data)
          .flat()
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
    if (result) {
      core.info(`User ${currentEventUserName} has enough permission to bypass the action`)
    } else {
      core.info(
        `User ${currentEventUserName} has not enough permission to bypass the action (not in ${allowUserTeams})`
      )
    }
    return result
  })
}

export async function isValidUser(
  context: typeof githubContext,
  octokit: ReturnType<typeof getOctokit>,
  currentEventUserName: string,
  allowUserNames: string[],
  allowUserTeams: string[]
) {
  if (allowUserNames.length === 0 && allowUserTeams.length === 0) {
    core.info('No user or team need to check, bypass the action')
    return true
  }
  return (
    (await isValidUserByName(currentEventUserName, allowUserNames)) ||
    (await isValidUserByTeam(context, octokit, currentEventUserName, allowUserTeams))
  )
}

export function withAllPages<T, U>(
  octokit: ReturnType<typeof getOctokit>,
  method: (params: T) => Promise<U>
): (params: T) => Promise<U[]> {
  return async (params: T): Promise<U[]> => {
    const allData: U[] = []
    for await (const response of octokit.paginate.iterator(method as any, {
      ...params,
      per_page: 100,
    })) {
      allData.push(response.data)
    }

    return allData
  }
}
