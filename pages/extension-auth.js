import Head from "next/head";
import { useEffect, useMemo, useState } from "react";
import { Turnstile } from "@marsidev/react-turnstile";
import { getSupabaseExtensionAuthClient } from "../lib/supabaseBrowser";

function validNonce(value) {
  return /^[a-f0-9]{36}$/i.test(String(value || ""));
}

export default function ExtensionAuth() {
  const supabase = useMemo(() => {
    if (typeof window === "undefined") return null;
    return getSupabaseExtensionAuthClient();
  }, []);
  const [session, setSession] = useState(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [captchaKey, setCaptchaKey] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const turnstileSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";

  useEffect(() => {
    if (!supabase) return undefined;
    supabase.auth.getSession().then(({ data }) => setSession(data.session || null));
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession || null);
    });
    return () => data.subscription.unsubscribe();
  }, [supabase]);

  useEffect(() => {
    if (typeof window === "undefined" || !session?.access_token || !session?.refresh_token) return;
    const nonce = new URLSearchParams(window.location.search).get("nonce") || "";
    if (!validNonce(nonce)) {
      setError("This extension connection has expired. Start it again from the Firefox sidebar.");
      return;
    }
    window.postMessage({
      type: "PLAYLISTPILOT_EXTENSION_SESSION",
      nonce,
      session: {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_at: session.expires_at,
        email: session.user?.email || "",
      },
    }, window.location.origin);
  }, [session?.access_token, session?.refresh_token, session?.expires_at, session?.user?.email]);

  async function signInWithGoogle() {
    if (!supabase || busy) return;
    setBusy(true);
    setError("");
    try {
      const { error: authError } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: { redirectTo: window.location.href },
      });
      if (authError) throw authError;
    } catch (authError) {
      setError(authError?.message || "Google sign-in failed.");
      setBusy(false);
    }
  }

  async function signInWithPassword(event) {
    event.preventDefault();
    if (!supabase || busy) return;
    setError("");
    if (!email.trim() || !password) return setError("Enter your email and password.");
    if (!turnstileSiteKey) return setError("Email sign-in is unavailable. Use Google sign-in.");
    if (!captchaToken) return setError("Complete the security check first.");
    setBusy(true);
    try {
      const { error: authError } = await supabase.auth.signInWithPassword({
        email: email.trim().toLowerCase(),
        password,
        options: { captchaToken },
      });
      if (authError) throw authError;
    } catch (authError) {
      setError(authError?.message || "Sign-in failed.");
      setCaptchaToken("");
      setCaptchaKey((value) => value + 1);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Head>
        <title>Connect PlaylistPilot Extension</title>
        <meta name="robots" content="noindex,nofollow" />
      </Head>
      <main className="extensionAuthPage">
        <section className="extensionAuthCard">
          <div className="brand">
            <img src="/playlistpilot-logo-v1.jpg" alt="" />
            <span><strong>PlaylistPilot</strong><small>Firefox curator extension</small></span>
          </div>
          {session ? (
            <div className="connecting">
              <span className="statusDot" />
              <h1>Connecting your extension…</h1>
              <p>This tab closes automatically when the secure session handoff is complete.</p>
            </div>
          ) : (
            <>
              <div className="intro">
                <span className="eyebrow">Secure account connection</span>
                <h1>Sign in once. Curate from the sidebar.</h1>
                <p>No active PlaylistPilot tab is required after this connection.</p>
              </div>
              <button className="googleButton" onClick={signInWithGoogle} disabled={busy}>
                Continue with Google
              </button>
              <div className="divider"><span>or use email</span></div>
              <form onSubmit={signInWithPassword}>
                <label>Email<input type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
                <label>Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
                {turnstileSiteKey ? (
                  <div className="captcha">
                    <Turnstile
                      key={captchaKey}
                      siteKey={turnstileSiteKey}
                      options={{ theme: "dark", size: "flexible" }}
                      onSuccess={setCaptchaToken}
                      onExpire={() => setCaptchaToken("")}
                    />
                  </div>
                ) : null}
                <button className="primaryButton" type="submit" disabled={busy}>Connect extension</button>
              </form>
              {error ? <p className="error">{error}</p> : null}
              <p className="privacy">Your password is sent directly to Supabase Auth and is never stored by the extension.</p>
            </>
          )}
        </section>
      </main>
      <style jsx global>{`
        * { box-sizing: border-box; }
        html, body, #__next { min-height: 100%; margin: 0; }
        body { background: #0f1318; color: #f4f7f5; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        .extensionAuthPage {
          min-height: 100vh; display: grid; place-items: center; padding: 28px;
          background:
            radial-gradient(circle at 50% -10%, rgba(36, 211, 102, .16), transparent 38%),
            linear-gradient(180deg, #11161d 0%, #0f1318 48%, #12161d 100%);
        }
        .extensionAuthCard {
          width: min(100%, 440px); padding: 24px; border: 1px solid rgba(255,255,255,.09);
          border-radius: 24px; background: rgba(20,25,32,.92); box-shadow: 0 28px 90px rgba(0,0,0,.42);
        }
        .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; }
        .brand img { width: 44px; height: 44px; border-radius: 13px; object-fit: cover; }
        .brand span { display: flex; flex-direction: column; }
        .brand strong { font-size: 16px; }
        .brand small, .intro p, .connecting p, .privacy { color: #aeb6c2; }
        .eyebrow { color: #24d366; font-size: 11px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }
        h1 { margin: 8px 0; font-size: clamp(25px, 7vw, 34px); line-height: 1.06; letter-spacing: -.04em; }
        .intro p, .connecting p { margin: 0 0 24px; line-height: 1.6; }
        button { width: 100%; min-height: 46px; border: 0; border-radius: 12px; font: inherit; font-weight: 800; cursor: pointer; }
        button:disabled { cursor: wait; opacity: .6; }
        .googleButton { border: 1px solid rgba(255,255,255,.13); background: #1b212a; color: #f4f7f5; }
        .primaryButton { margin-top: 15px; background: #24d366; color: #08100c; }
        .divider { display: flex; align-items: center; gap: 12px; margin: 20px 0; color: #7f8998; font-size: 11px; }
        .divider::before, .divider::after { content: ""; height: 1px; flex: 1; background: rgba(255,255,255,.08); }
        label { display: grid; gap: 7px; margin-top: 12px; color: #aeb6c2; font-size: 12px; font-weight: 700; }
        input { min-height: 44px; border: 1px solid #2a303b; border-radius: 11px; outline: none; background: #101318; color: #f4f7f5; padding: 10px 12px; font: inherit; }
        input:focus { border-color: #24d366; box-shadow: 0 0 0 3px rgba(36,211,102,.12); }
        .captcha { margin-top: 14px; }
        .error { padding: 10px 12px; border-radius: 10px; background: rgba(255,77,77,.1); color: #ff8585; font-size: 12px; }
        .privacy { margin: 18px 0 0; font-size: 11px; line-height: 1.5; text-align: center; }
        .connecting { padding: 30px 4px 18px; text-align: center; }
        .statusDot { display: inline-block; width: 14px; height: 14px; border-radius: 50%; background: #24d366; box-shadow: 0 0 0 8px rgba(36,211,102,.12); animation: pulse 1.2s infinite alternate; }
        @keyframes pulse { to { box-shadow: 0 0 0 14px rgba(36,211,102,.03); } }
      `}</style>
    </>
  );
}
