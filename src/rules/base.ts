export interface Rule {
  type: string
  check(context: any): Promise<boolean>
}

export abstract class AbstractRule implements Rule {
  abstract type: string
  abstract check(context: any): Promise<boolean>

  static fromObject(obj: any): AbstractRule {
    throw new Error('fromObject method must be implemented')
  }
}

export class RuleFactory {
  private static instance: RuleFactory
  private ruleClasses = new Map<string, typeof AbstractRule>()

  private constructor() {}

  static getInstance(): RuleFactory {
    if (!RuleFactory.instance) {
      RuleFactory.instance = new RuleFactory()
    }
    return RuleFactory.instance
  }

  registerRuleType(type: string, ruleClass: typeof AbstractRule) {
    this.ruleClasses.set(type, ruleClass)
  }

  getRuleClass(type: string): typeof AbstractRule | undefined {
    return this.ruleClasses.get(type)
  }
}

export async function checkRule(rule: any, context: any): Promise<boolean> {
  if (!rule || typeof rule !== 'object' || !rule.type) {
    throw new Error('Invalid rule object')
  }
  const ruleInstance = RuleFactory.getInstance().getRuleClass(rule.type)?.fromObject(rule)
  if (!ruleInstance) {
    throw new Error(`Unsupported rule type: ${rule.type}`)
  }
  return await ruleInstance.check(context)
}
