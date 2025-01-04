import { AbstractRule } from './base'

export class LabelRule extends AbstractRule {
  public static type: string = 'labeled'
  public label: string | string[]
  public userName: string | string[] | null
  public userTeam: string | string[] | null
  constructor(
    label: string | string[],
    userName: string | string[] | undefined,
    userTeam: string | string[] | undefined
  ) {
    super()
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
