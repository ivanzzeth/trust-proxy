// Talking to the desktop shell, when the console is running inside it.
//
// The console is served by the gateway over loopback and shown in the shell's
// window, so it is a *remote* page as far as Tauri is concerned: `window.__TAURI__`
// only exists because the bundle grants this origin IPC (see
// desktop/src-tauri/capabilities/console.json). In a browser it is simply absent,
// and every function here is a no-op — the same build serves both.
//
// There is exactly one thing the console needs from the shell: elevation. TUN needs
// a root gateway, the window must never be root, and a web page cannot ask macOS
// for an admin prompt. Without this the TUN switch could only print instructions
// and tell the user to go and find a terminal.

type TauriInvoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

function invoker(): TauriInvoke | null {
  const w = window as unknown as { __TAURI__?: { core?: { invoke?: TauriInvoke } } };
  return w.__TAURI__?.core?.invoke ?? null;
}

/** Is this console being shown inside the desktop app? */
export function inDesktopApp(): boolean {
  return invoker() !== null;
}

/**
 * Ask the shell to install the gateway as a system service, optionally pinning a
 * capture mode. The shell raises one platform admin prompt, stops any gateway it
 * had started itself, and re-attaches to the service.
 */
export async function installServiceViaApp(mode?: 'manual' | 'system' | 'tun'): Promise<string> {
  const invoke = invoker();
  if (!invoke) throw new Error('not running in the desktop app');
  return invoke<string>('install_service', { mode });
}
