/**
 * Copy text to the clipboard, reporting whether it worked.
 *
 * `navigator.clipboard` requires a secure context, and the console is served on
 * :21585 over plain HTTP — which several browsers do not consider secure. The API
 * is then simply absent, so an unguarded `navigator.clipboard?.writeText(x)`
 * does nothing at all and says nothing about it: the operator walks away
 * believing they hold an API key or a subscription URL that never left the page.
 *
 * The execCommand fallback is deprecated but still the only thing that works in
 * an insecure context. Callers decide what to say; this only reports success.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy path
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
