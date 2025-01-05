import { getOctokit } from '@actions/github'
import * as core from '@actions/core'
import { AbstractRule } from './base.js'
import { PullRequestContext } from '../context.js'
import {
  resolveMaybeOneOrMoreOption,
  resolveOneOrMoreOption,
  isValidUserByName,
  isValidUserByTeam,
} from './utils.js'

interface CommentWithActor {
  content: string
  actor: string
}

function compilePattern(pattern: string): RegExp {
  return new RegExp(pattern, 'g')
}

export class CommentRule extends AbstractRule {
  public static type: string = 'commented'
  public messagePatterns: RegExp[]
  public userNames: string[]
  public userTeams: string[]
  constructor(
    messagePattern: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
    this.messagePatterns = resolveOneOrMoreOption(messagePattern).map(compilePattern)
    this.userNames = resolveMaybeOneOrMoreOption(userName)
    this.userTeams = resolveMaybeOneOrMoreOption(userTeam)
  }

  public async check(context: PullRequestContext): Promise<boolean> {
    const { githubToken, githubContext } = context
    const octokit = getOctokit(githubToken)
    const { owner, repo } = githubContext.repo
    const { number } = githubContext.issue
    const allCommentResponse = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number: number,
    })
    const allCommentWithActors = allCommentResponse.data
      .map((comment) => {
        if (!comment.user) {
          core.warning(`comment.user is undefined, comment: ${comment}`)
          return undefined
        }
        if (!comment.body) {
          core.warning(`comment.body is undefined, comment: ${comment}`)
          return undefined
        }
        return { content: comment.body, actor: comment.user.login }
      })
      .filter((comment): comment is CommentWithActor => comment !== undefined)
      .filter((comment) => this.messagePatterns.some((pattern) => pattern.test(comment.content)))
    const IsValidComment = async (comment: CommentWithActor): Promise<Boolean> => {
      const currentCommentUserName = comment.actor
      return (
        (await isValidUserByName(currentCommentUserName, this.userNames)) ||
        (await isValidUserByTeam(githubContext, octokit, currentCommentUserName, this.userTeams))
      )
    }
    core.debug(`allCommentWithActors: ${JSON.stringify(allCommentWithActors)}`)
    core.debug(`messagePatterns: ${JSON.stringify(this.messagePatterns)}`)
    return await Promise.all(allCommentWithActors.map(IsValidComment)).then((results) =>
      results.some((result) => result)
    )
  }

  public static fromObject(obj: any): CommentRule {
    return new CommentRule(obj['message-pattern'], obj['username'], obj['user-team'])
  }
}
