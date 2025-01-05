import { describe, it } from 'vitest'
import { ByPassCheckerBuilder } from '../src/rules/index.js'
import { AbstractRule } from '../src/rules/base.js'
import { type PullRequestContext } from '../src/context.js'

describe.concurrent('Test Rules', () => {
  class TestRule extends AbstractRule {
    public static type: string = 'test'
    constructor() {
      super()
    }
    public async check(context: any): Promise<boolean> {
      return true
    }
    public static fromObject(obj: any): TestRule {
      return new TestRule()
    }
  }

  it('check e2e basic', async ({ expect }) => {
    const rule = {
      type: 'test',
    }
    const bypassChecker = new ByPassCheckerBuilder().use(TestRule).build()
    expect(await bypassChecker.check(rule, {} as PullRequestContext)).toBe(true)
  })

  it('check e2e invalid rule', async ({ expect }) => {
    const rule = {}
    const bypassChecker = new ByPassCheckerBuilder().use(TestRule).build()
    await expect(
      async () => await bypassChecker.check(rule, {} as PullRequestContext)
    ).rejects.toThrowError('Invalid rule object')
  })

  it('check e2e unsupported rule', async ({ expect }) => {
    const rule = {
      type: 'unsupported',
    }
    const bypassChecker = new ByPassCheckerBuilder().use(TestRule).build()
    await expect(
      async () => await bypassChecker.check(rule, {} as PullRequestContext)
    ).rejects.toThrowError('Unsupported rule type: unsupported')
  })
})
