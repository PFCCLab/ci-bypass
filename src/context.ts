import { context } from '@actions/github'

export class PullRequestContext {
  constructor(
    public githubToken: string,
    public githubContext: typeof context
  ) {}
}
