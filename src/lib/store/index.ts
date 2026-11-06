import { resolveStoreMode, type ForgeStore } from './types';
import { MemoryStore } from './memory';

const globalRef = globalThis as unknown as { __aiForgeStore?: ForgeStore };

/**
 * Returns the active ForgeStore (Prisma when DATABASE_URL is set, else memory).
 * Override with AI_FORGE_STORE=memory|prisma.
 */
export async function getStore(): Promise<ForgeStore> {
  if (globalRef.__aiForgeStore) {
    await globalRef.__aiForgeStore.ensureSeed();
    return globalRef.__aiForgeStore;
  }

  const mode = resolveStoreMode();
  let store: ForgeStore;

  if (mode === 'prisma') {
    try {
      const { PrismaStore } = await import('./prisma-store');
      store = new PrismaStore();
      // Probe connectivity
      await store.ensureSeed();
    } catch (err) {
      console.warn(
        '[ai-forge] Prisma store unavailable, falling back to memory:',
        err instanceof Error ? err.message : err
      );
      store = new MemoryStore();
      await store.ensureSeed();
    }
  } else {
    store = new MemoryStore();
    await store.ensureSeed();
  }

  globalRef.__aiForgeStore = store;
  return store;
}

/** Force a fresh store instance (tests). */
export function clearStoreCache() {
  globalRef.__aiForgeStore = undefined;
}

export type { ForgeStore } from './types';
export { resolveStoreMode } from './types';
export { resetMemoryStore } from './memory';
