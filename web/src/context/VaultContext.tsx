import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes of inactivity

interface VaultContextValue {
  /** Base64-encoded vault key in memory; null when locked. */
  vaultKey: string | null;
  setVaultKey: (key: string) => void;
  lock: () => void;
}

const VaultContext = createContext<VaultContextValue>({
  vaultKey: null,
  setVaultKey: () => {},
  lock: () => {},
});

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [vaultKey, setVaultKeyState] = useState<string | null>(null);
  const lockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lock = useCallback(() => {
    setVaultKeyState(null);
    if (lockTimer.current !== null) {
      clearTimeout(lockTimer.current);
      lockTimer.current = null;
    }
  }, []);

  const resetTimer = useCallback(() => {
    if (lockTimer.current !== null) clearTimeout(lockTimer.current);
    lockTimer.current = setTimeout(lock, AUTO_LOCK_MS);
  }, [lock]);

  const setVaultKey = useCallback(
    (key: string) => {
      setVaultKeyState(key);
      resetTimer();
    },
    [resetTimer]
  );

  // Reset inactivity timer on any user interaction while unlocked.
  useEffect(() => {
    if (vaultKey === null) return;
    const events = ["mousemove", "keydown", "click", "touchstart"] as const;
    const handler = () => resetTimer();
    events.forEach((e) => window.addEventListener(e, handler, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, handler));
  }, [vaultKey, resetTimer]);

  // Lock immediately when the tab is hidden (browser/OS switch).
  useEffect(() => {
    const handler = () => {
      if (document.visibilityState === "hidden") lock();
    };
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, [lock]);

  return (
    <VaultContext.Provider value={{ vaultKey, setVaultKey, lock }}>
      {children}
    </VaultContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export const useVault = () => useContext(VaultContext);
