import { AbstractRule, type RuleClass } from './base'

type RuleConstructor = (new (...args: any[]) => AbstractRule) & RuleClass

export class ByPassChecker {
  private ruleClasses: Map<string, RuleConstructor>
  public constructor(ruleClasses: Map<string, RuleConstructor>) {
    this.ruleClasses = ruleClasses
  }
  public async check(rule: any, context: any): Promise<boolean> {
    if (!rule || typeof rule !== 'object' || !rule.type) {
      throw new Error('Invalid rule object')
    }
    console.log(this.ruleClasses)
    const ruleInstance = this.getRuleClass(rule.type)?.fromObject(rule)
    if (!ruleInstance) {
      throw new Error(`Unsupported rule type: ${rule.type}`)
    }
    return await ruleInstance.check(context)
  }
  private getRuleClass(type: string): RuleConstructor | undefined {
    return this.ruleClasses.get(type)
  }
}

export class ByPassCheckerBuilder {
  private ruleClasses = new Map<string, RuleConstructor>()
  public constructor() {}
  public use(ruleClass: RuleConstructor): ByPassCheckerBuilder {
    this.ruleClasses.set(ruleClass.type, ruleClass)
    return this
  }
  public build(): ByPassChecker {
    return new ByPassChecker(this.ruleClasses)
  }
}
