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

interface CommentWithActor {
  content: string
  actor: string
}

function compilePattern(pattern: string): RegExp {
  return new RegExp(pattern, 'g')
}

export class CommentRule extends AbstractRule {
  public static type: string = 'commented'
  public commentPatterns: RegExp[]
  public userNames: string[]
  public userTeams: string[]
  constructor(
    commentPattern: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
    this.commentPatterns = resolveOneOrMoreOption(commentPattern).map(compilePattern)
    this.userNames = resolveMaybeOneOrMoreOption(userName)
    this.userTeams = resolveMaybeOneOrMoreOption(userTeam)
  }

  public async check(context: PullRequestContext): Promise<boolean> {
    const { githubToken, githubContext } = context
    const octokit = getOctokit(githubToken)
    const { owner, repo } = githubContext.repo
    const { number } = githubContext.issue
    const allCommentResponse = (
      await withAllPages(
        octokit,
        octokit.rest.issues.listComments
      )({
        owner,
        repo,
        issue_number: number,
      })
    )
      .map((rawData) => rawData.data)
      .flat()
    const allCommentWithActors = allCommentResponse
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
      .filter((comment) => this.commentPatterns.some((pattern) => pattern.test(comment.content)))
    const IsValidComment = async (comment: CommentWithActor): Promise<Boolean> => {
      const currentCommentUserName = comment.actor
      return await isValidUser(
        githubContext,
        octokit,
        currentCommentUserName,
        this.userNames,
        this.userTeams
      )
    }
    core.debug(`allCommentWithActors: ${JSON.stringify(allCommentWithActors)}`)
    core.debug(`messagePatterns: ${JSON.stringify(this.commentPatterns)}`)
    return await Promise.all(allCommentWithActors.map(IsValidComment)).then((results) =>
      results.some((result) => result)
    )
  }

  public static fromObject(obj: any): CommentRule {
    return new CommentRule(obj['comment-pattern'], obj['username'], obj['user-team'])
  }
}
