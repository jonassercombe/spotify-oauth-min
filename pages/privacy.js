import Head from "next/head";

export default function PrivacyPage() {
  return (
    <>
      <Head>
        <title>Privacy Policy | PlaylistPilot</title>
        <meta name="description" content="Privacy policy for PlaylistPilot and the PlaylistPilot Curator Firefox extension." />
        <meta name="robots" content="index,follow" />
        <link rel="canonical" href="https://playlist-pilot.com/privacy" />
      </Head>
      <main>
        <a className="back" href="/">← PlaylistPilot</a>
        <h1>Privacy Policy</h1>
        <p className="updated">Last updated: August 22, 2026</p>

        <p>PlaylistPilot provides playlist-management software and the PlaylistPilot Curator Firefox extension. This policy explains what information these products process and why.</p>

        <h2>Information processed by the extension</h2>
        <ul>
          <li><strong>Authentication information:</strong> the PlaylistPilot session required to connect the extension to your account. Platform passwords are not collected or stored.</li>
          <li><strong>Website content:</strong> visible submission details on supported curator websites, including track title, artist, Spotify track ID, selected playlist, deadlines, counters and confirmation state.</li>
          <li><strong>Communications you provide:</strong> feedback notes, examples and generated feedback drafts when you use the feedback tools.</li>
          <li><strong>Local configuration:</strong> account labels, Firefox Container mappings, scan snapshots, workflow preferences and feedback profiles.</li>
        </ul>

        <h2>How information is used</h2>
        <p>Information is used only to provide requested PlaylistPilot functions: organizing curator sessions, showing submission statistics, generating feedback, recording confirmed playlist acceptances and applying playlist-specific expiry rules. PlaylistPilot does not sell personal information or use curator-page content for advertising.</p>

        <h2>Local and server storage</h2>
        <p>Session mappings, interface preferences and cached scan results are stored locally in Firefox. Account data, feedback profiles and confirmed acceptance records may be stored in PlaylistPilot’s Supabase-backed account database so they remain available across installations. Removing the extension clears Firefox-managed extension storage; it does not automatically delete records stored in your PlaylistPilot account.</p>

        <h2>Feedback generation</h2>
        <p>Feedback text and a limited selection of writing examples are transmitted to PlaylistPilot only after you explicitly request generation. PlaylistPilot uses an AI service provider to produce the draft. Generated text is never submitted to a curator platform automatically.</p>

        <h2>Third-party services</h2>
        <p>PlaylistPilot uses Supabase for authentication and application data, Spotify for playlist and playback functionality, OpenAI for requested feedback generation, and Vercel for application hosting. Supported curator websites remain governed by their own privacy policies and terms.</p>

        <h2>Your choices and deletion</h2>
        <p>You can disconnect PlaylistPilot, remove stored session profiles, delete local extension data, or uninstall the extension at any time. To request deletion of server-side account information, email <a href="mailto:jonassercombe@googlemail.com">jonassercombe@googlemail.com</a>.</p>

        <h2>Security and changes</h2>
        <p>PlaylistPilot uses authenticated HTTPS connections and limits extension access to PlaylistPilot, SubmitHub, Groover and PlaylistPush. This policy may be updated as the product changes. Material changes will be reflected by the date above.</p>

        <h2>Contact</h2>
        <p>Questions about privacy can be sent to <a href="mailto:jonassercombe@googlemail.com">jonassercombe@googlemail.com</a>.</p>
      </main>
      <style jsx>{`
        :global(body) { margin: 0; background: #0f1318; color: #f4f7f5; font: 16px/1.65 Inter, system-ui, sans-serif; }
        main { width: min(760px, calc(100% - 40px)); margin: 0 auto; padding: 48px 0 80px; }
        .back, a { color: #24d366; }
        .back { text-decoration: none; }
        h1 { margin: 36px 0 0; font-size: clamp(36px, 7vw, 58px); line-height: 1.05; }
        h2 { margin: 34px 0 8px; font-size: 21px; }
        p, li { color: #bdc5cf; }
        strong { color: #f4f7f5; }
        .updated { margin-top: 8px; color: #7f8998; }
      `}</style>
    </>
  );
}
