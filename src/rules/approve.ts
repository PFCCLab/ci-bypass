import { getOctokit } from '@actions/github'
import * as core from '@actions/core'
import { AbstractRule } from './base.js'
import { PullRequestContext } from '../context.js'
import { resolveMaybeOneOrMoreOption, isValidUser } from './utils.js'

interface ReviewWithActor {
  state: string
  actor: string
}

export class ApproveRule extends AbstractRule {
  public static type: string = 'approved'
  public userNames: string[]
  public userTeams: string[]
  constructor(userName: string | string[] | undefined, userTeam: string | string[] | undefined) {
    super()
    this.userNames = resolveMaybeOneOrMoreOption(userName)
    this.userTeams = resolveMaybeOneOrMoreOption(userTeam)
  }

  public async check(context: PullRequestContext): Promise<boolean> {
    const { githubToken, githubContext } = context
    const octokit = getOctokit(githubToken)
    const { owner, repo } = githubContext.repo
    const { number } = githubContext.issue
    const allReviewResponse = await octokit.rest.pulls.listReviews({
      owner,
      repo,
      pull_number: number,
    })
    const allReviewWithActors = allReviewResponse.data
      .map((review) => {
        if (!review.user) {
          core.warning(`review.user is undefined, review: ${review}`)
          return undefined
        }
        return { state: review.state, actor: review.user.login }
      })
      .filter((review): review is ReviewWithActor => review !== undefined)
    let requestChangesReviewers = new Set<string>()
    const IsValidReview = async (review: ReviewWithActor): Promise<Boolean> => {
      const currentReviewUserName = review.actor
      if (review.state === 'CHANGES_REQUESTED') {
        requestChangesReviewers.add(currentReviewUserName)
      }
      if (requestChangesReviewers.has(currentReviewUserName)) {
        core.info(`User ${currentReviewUserName} has requested changes`)
        return false
      }
      return (
        review.state === 'APPROVED' &&
        (await isValidUser(
          githubContext,
          octokit,
          currentReviewUserName,
          this.userNames,
          this.userTeams
        ))
      )
    }
    for (const review of allReviewWithActors.reverse()) {
      if (await IsValidReview(review)) {
        return true
      }
    }
    core.debug(`No valid review found, all reviews: ${allReviewWithActors}`)
    return false
  }

  public static fromObject(obj: any): ApproveRule {
    return new ApproveRule(obj['username'], obj['user-team'])
  }
}
