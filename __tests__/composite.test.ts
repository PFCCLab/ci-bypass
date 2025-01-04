import { describe, it, assert } from 'vitest'
import { isCompositeTrue, isCompositeTrueAsync } from '../src/composite'

describe.concurrent('Test Composite', () => {
  function booleanIdentityWithTypeCheck(value: any): boolean {
    assert(typeof value === 'boolean')
    return value
  }

  // Check basic
  it('basic bool true', async ({ expect }) => {
    expect(isCompositeTrue(true, booleanIdentityWithTypeCheck)).toBe(true)
  })
  it('basic bool false', async ({ expect }) => {
    expect(isCompositeTrue(false, booleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check composite any
  it('any composite true', async ({ expect }) => {
    expect(isCompositeTrue({ any: [true, false] }, booleanIdentityWithTypeCheck)).toBe(true)
  })
  it('any composite false', async ({ expect }) => {
    expect(isCompositeTrue({ any: [false, false] }, booleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check composite all
  it('all composite true', async ({ expect }) => {
    expect(isCompositeTrue({ all: [true, true] }, booleanIdentityWithTypeCheck)).toBe(true)
  })
  it('all composite false', async ({ expect }) => {
    expect(isCompositeTrue({ all: [true, false] }, booleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check composite not
  it('not composite true', async ({ expect }) => {
    expect(isCompositeTrue({ not: false }, booleanIdentityWithTypeCheck)).toBe(true)
  })
  it('not composite false', async ({ expect }) => {
    expect(isCompositeTrue({ not: true }, booleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check mixed composite
  it('mixed composite case1', async ({ expect }) => {
    expect(
      isCompositeTrue(
        { any: [{ all: [true, { not: false }] }, false] },
        booleanIdentityWithTypeCheck
      )
    ).toBe(true)
  })
  it('mixed composite case2', async ({ expect }) => {
    expect(
      isCompositeTrue(
        { any: [{ all: [true, { not: true }] }, false] },
        booleanIdentityWithTypeCheck
      )
    ).toBe(false)
  })
  it('mixed composite case3', async ({ expect }) => {
    expect(
      isCompositeTrue(
        { all: [true, { not: { any: [false, false, false] } }, true] },
        booleanIdentityWithTypeCheck
      )
    ).toBe(true)
  })

  function greaterThan10(value: number): boolean {
    return value > 10
  }

  // Check non-booleans
  it('non-boolean type case1', async ({ expect }) => {
    expect(isCompositeTrue(42, greaterThan10)).toBe(true)
  })
  it('non-boolean type case2', async ({ expect }) => {
    expect(isCompositeTrue({ any: [42, 3] }, greaterThan10)).toBe(true)
  })
  it('non-boolean type case3', async ({ expect }) => {
    expect(isCompositeTrue({ all: [42, 3] }, greaterThan10)).toBe(false)
  })
})

describe.concurrent('Test Composite with async', () => {
  async function asyncBooleanIdentityWithTypeCheck(value: any): Promise<boolean> {
    assert(typeof value === 'boolean')
    return value
  }

  // Check basic
  it('basic bool true', async ({ expect }) => {
    expect(await isCompositeTrueAsync(true, asyncBooleanIdentityWithTypeCheck)).toBe(true)
  })
  it('basic bool false', async ({ expect }) => {
    expect(await isCompositeTrueAsync(false, asyncBooleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check composite any
  it('any composite true', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync({ any: [true, false] }, asyncBooleanIdentityWithTypeCheck)
    ).toBe(true)
  })
  it('any composite false', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync({ any: [false, false] }, asyncBooleanIdentityWithTypeCheck)
    ).toBe(false)
  })

  // Check composite all
  it('all composite true', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync({ all: [true, true] }, asyncBooleanIdentityWithTypeCheck)
    ).toBe(true)
  })
  it('all composite false', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync({ all: [true, false] }, asyncBooleanIdentityWithTypeCheck)
    ).toBe(false)
  })

  // Check composite not
  it('not composite true', async ({ expect }) => {
    expect(await isCompositeTrueAsync({ not: false }, asyncBooleanIdentityWithTypeCheck)).toBe(true)
  })
  it('not composite false', async ({ expect }) => {
    expect(await isCompositeTrueAsync({ not: true }, asyncBooleanIdentityWithTypeCheck)).toBe(false)
  })

  // Check mixed composite
  it('mixed composite case1', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync(
        { any: [{ all: [true, { not: false }] }, false] },
        asyncBooleanIdentityWithTypeCheck
      )
    ).toBe(true)
  })
  it('mixed composite case2', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync(
        { any: [{ all: [true, { not: true }] }, false] },
        asyncBooleanIdentityWithTypeCheck
      )
    ).toBe(false)
  })
  it('mixed composite case3', async ({ expect }) => {
    expect(
      await isCompositeTrueAsync(
        {
          all: [
            true,
            {
              not: { any: [false, false, false] },
            },
            true,
          ],
        },
        asyncBooleanIdentityWithTypeCheck
      )
    ).toBe(true)
  })

  async function asyncGreaterThan10(value: number): Promise<boolean> {
    return value > 10
  }

  // Check non-booleans
  it('non-boolean type case1', async ({ expect }) => {
    expect(await isCompositeTrueAsync(42, asyncGreaterThan10)).toBe(true)
  })
  it('non-boolean type case2', async ({ expect }) => {
    expect(await isCompositeTrueAsync({ any: [42, 3] }, asyncGreaterThan10)).toBe(true)
  })
  it('non-boolean type case3', async ({ expect }) => {
    expect(await isCompositeTrueAsync({ all: [42, 3] }, asyncGreaterThan10)).toBe(false)
  })
})
