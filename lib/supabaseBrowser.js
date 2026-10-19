import { createClient, navigatorLock } from "@supabase/supabase-js";

let browserClient;
let extensionAuthClient;

function browserConfig(storageKey) {
  return {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      // Firefox can reject Supabase's non-blocking (0 ms) Web Lock attempt
      // while another tab is refreshing the same session. Waiting briefly keeps
      // refresh-token rotation serialized across PlaylistPilot tabs and avoids
      // an otherwise unhandled NavigatorLockAcquireTimeoutError.
      lock: (name, acquireTimeout, fn) => navigatorLock(
        name,
        acquireTimeout === 0 ? 5000 : acquireTimeout,
        fn
      ),
      ...(storageKey ? { storageKey } : {}),
    },
  };
}

export function getSupabaseBrowserClient() {
  if (browserClient) return browserClient;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!url || !key) {
    throw new Error("Missing Supabase browser environment variables");
  }

  browserClient = createClient(url, key, browserConfig());

  return browserClient;
}

export function getSupabaseExtensionAuthClient() {
  if (extensionAuthClient) return extensionAuthClient;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!url || !key) {
    throw new Error("Missing Supabase browser environment variables");
  }

  // The extension owns an independent rotating refresh-token chain. Sharing the
  // website session here lets either client invalidate the other's next refresh.
  extensionAuthClient = createClient(url, key, browserConfig("playlistpilot-extension-auth-v1"));
  return extensionAuthClient;
}
