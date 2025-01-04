import { PullRequestContext } from '../context'

export interface Rule {
  check(context: any): Promise<boolean>
}

export interface RuleClass {
  type: string
  fromObject(obj: any): Rule
}

export abstract class AbstractRule implements Rule {
  static type: string
  abstract check(context: PullRequestContext): Promise<boolean>

  static fromObject(obj: any): AbstractRule {
    throw new Error('fromObject method must be implemented')
  }
}

export type RuleConstructor = (new (...args: any[]) => AbstractRule) & RuleClass
