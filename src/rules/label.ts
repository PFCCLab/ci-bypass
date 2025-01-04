import { AbstractRule, RuleFactory } from './base'

export class LabelRule extends AbstractRule {
  public type: string
  public label: string | string[]
  public userName: string | string[] | null
  public userTeam: string | string[] | null
  constructor(
    label: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
    this.type = 'labeled'
    this.label = label
    this.userName = userName ?? null
    this.userTeam = userTeam ?? null
  }

  public async check(context: any): Promise<boolean> {
    return true
  }

  public static fromObject(obj: any): LabelRule {
    return new LabelRule(obj.label, obj.userName, obj.userTeam)
  }
}
RuleFactory.getInstance().registerRuleType('labeled', LabelRule as unknown as typeof AbstractRule)
