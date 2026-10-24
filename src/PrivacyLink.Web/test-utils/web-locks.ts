export function installTestWebLocks(): () => void {
  const queues = new Map<string, Promise<void>>();
  const locks = {
    request: async (
      name: string,
      _options: LockOptions,
      callback: (lock: Lock | null) => unknown | Promise<unknown>
    ): Promise<unknown> => {
      const previous = queues.get(name) ?? Promise.resolve();
      let release!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; });
      const tail = previous.then(() => gate);
      queues.set(name, tail);
      await previous;
      try {
        return await callback({ name, mode: 'exclusive' } as Lock);
      } finally {
        release();
        if (queues.get(name) === tail) queues.delete(name);
      }
    }
  } as unknown as LockManager;

  const descriptor = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: locks });
  return () => {
    if (descriptor) Object.defineProperty(navigator, 'locks', descriptor);
    else Reflect.deleteProperty(navigator, 'locks');
  };
}
