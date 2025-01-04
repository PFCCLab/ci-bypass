interface AnyComposite<T> {
  any: T[]
}

interface AllComposite<T> {
  all: T[]
}

interface NotComposite<T> {
  not: T
}

type Composite<T> =
  | T
  | AnyComposite<T | Composite<T>>
  | AllComposite<T | Composite<T>>
  | NotComposite<T | Composite<T>>

function isAnyComposite<T>(composite: Composite<T>): composite is AnyComposite<T> {
  return (composite as AnyComposite<T>).any !== undefined
}

function isAllComposite<T>(composite: Composite<T>): composite is AllComposite<T> {
  return (composite as AllComposite<T>).all !== undefined
}

function isNotComposite<T>(composite: Composite<T>): composite is NotComposite<T> {
  return (composite as NotComposite<T>).not !== undefined
}

function resolveAnyCompositeHighterOrder<T>(
  predicate: (value: T) => boolean
): (composite: AnyComposite<T>) => boolean {
  return (composite: AnyComposite<T>) => composite.any.some(predicate)
}

function resolveAllComposite<T>(
  predicate: (value: T) => boolean
): (composite: AllComposite<T>) => boolean {
  return (composite: AllComposite<T>) => composite.all.every(predicate)
}

function resolveNotComposite<T>(
  predicate: (value: T) => boolean
): (composite: NotComposite<T>) => boolean {
  return (composite: NotComposite<T>) => !predicate(composite.not)
}

export function resolveComposite<T>(
  predicate: (value: T) => boolean
): (composite: Composite<T>) => boolean {
  function predicateForComposite(value: Composite<T>): boolean {
    return resolveComposite(predicate)(value)
  }
  return (composite: Composite<T>) => {
    if (isAnyComposite(composite)) {
      return resolveAnyCompositeHighterOrder(predicateForComposite)(composite)
    } else if (isAllComposite(composite)) {
      return resolveAllComposite(predicateForComposite)(composite)
    } else if (isNotComposite(composite)) {
      return resolveNotComposite(predicateForComposite)(composite)
    } else {
      return predicate(composite as T)
    }
  }
}

export function isCompositeTrue<T>(
  composite: Composite<T>,
  predicate: (value: T) => boolean
): boolean {
  return resolveComposite(predicate)(composite)
}

function resolveCompositeAnyAsync<T>(
  predicate: (value: T) => Promise<boolean>
): (composite: AnyComposite<T>) => Promise<boolean> {
  return async (composite: AnyComposite<T>) => {
    const results = await Promise.all(composite.any.map(async (value) => await predicate(value)))
    return results.some((value) => value)
  }
}

function resolveCompositeAllAsync<T>(
  predicate: (value: T) => Promise<boolean>
): (composite: AllComposite<T>) => Promise<boolean> {
  return async (composite: AllComposite<T>) => {
    const results = await Promise.all(composite.all.map(async (value) => await predicate(value)))
    return results.every((value) => value)
  }
}

function resolveCompositeNotAsync<T>(
  predicate: (value: T) => Promise<boolean>
): (composite: NotComposite<T>) => Promise<boolean> {
  return async (composite: NotComposite<T>) => !(await predicate(composite.not))
}

export function resolveCompositeAsync<T>(
  predicate: (value: T) => Promise<boolean>
): (composite: Composite<T>) => Promise<boolean> {
  async function predicateForComposite(value: Composite<T>): Promise<boolean> {
    return resolveCompositeAsync(predicate)(value)
  }
  return async (composite: Composite<T>) => {
    if (isAnyComposite(composite)) {
      return resolveCompositeAnyAsync(predicateForComposite)(composite)
    } else if (isAllComposite(composite)) {
      return resolveCompositeAllAsync(predicateForComposite)(composite)
    } else if (isNotComposite(composite)) {
      return resolveCompositeNotAsync(predicateForComposite)(composite)
    } else {
      return await predicate(composite as T)
    }
  }
}

export async function isCompositeTrueAsync<T>(
  composite: Composite<T>,
  predicate: (value: T) => Promise<boolean>
): Promise<boolean> {
  return resolveCompositeAsync(predicate)(composite)
}
