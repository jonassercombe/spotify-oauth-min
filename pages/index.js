import Head from "next/head";
import { ArrowRight, BarChart3, Check, Clock3, Lock, RotateCcw, ShieldCheck, Sparkles } from "lucide-react";

const features = [
  {
    icon: Lock,
    title: "Position Locks",
    text: "Keep key songs exactly where they belong. PlaylistPilot checks your playlist and moves locked tracks back into place.",
  },
  {
    icon: Clock3,
    title: "Expiry Rules",
    text: "Automatically remove unlocked tracks after your chosen age limit, with per-song overrides for special cases.",
  },
  {
    icon: RotateCcw,
    title: "Track Rotator",
    text: "Reserve rotator positions and refresh them from your own source playlist on a daily, weekly, or monthly schedule.",
  },
  {
    icon: BarChart3,
    title: "Growth Dashboard",
    text: "Watch follower movement, upcoming removals, playlist health and performance trends from one focused dashboard.",
  },
];

const workflow = [
  "Sign in with Google",
  "Connect one or more Spotify accounts",
  "Choose a playlist and set your rules",
  "Let PlaylistPilot keep the playlist clean",
];

export default function LandingPage() {
  return (
    <main>
      <Head>
        <title>PlaylistPilot | Smart Spotify Playlist Management</title>
        <meta
          name="description"
          content="PlaylistPilot helps Spotify curators manage playlists with position locks, expiry timers, rotating song slots, backups and growth analytics."
        />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta property="og:title" content="PlaylistPilot" />
        <meta property="og:description" content="Smart Spotify playlist management for curators, labels and playlist operators." />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://playlist-pilot.com" />
        <meta property="og:image" content="https://playlist-pilot.com/playlistpilot-logo-v1.jpg" />
        <meta name="twitter:card" content="summary_large_image" />
        <link rel="icon" href="/playlistpilot-logo-v1.jpg" />
        <link rel="apple-touch-icon" href="/playlistpilot-logo-v1.jpg" />
        <link rel="canonical" href="https://playlist-pilot.com" />
      </Head>

      <header className="siteHeader">
        <a className="brand" href="/" aria-label="PlaylistPilot home">
          <img src="/playlistpilot-logo-v1.jpg" alt="" />
          <span>PlaylistPilot</span>
        </a>
        <nav aria-label="Main navigation">
          <a href="#features">Features</a>
          <a href="#pricing">Pricing</a>
          <a className="navCta" href="/app">Log in</a>
        </nav>
      </header>

      <section className="hero">
        <div className="heroCopy">
          <span className="eyebrow"><Sparkles aria-hidden="true" /> Spotify playlist operations, without spreadsheet chaos</span>
          <h1>PlaylistPilot</h1>
          <p>
            A professional control center for curators who need stable playlist positions, automatic cleanup,
            rotating discovery slots, backups and growth insight across Spotify accounts.
          </p>
          <div className="heroActions">
            <a className="primaryButton" href="/app">Start managing playlists <ArrowRight aria-hidden="true" /></a>
            <a className="secondaryButton" href="#features">Explore features</a>
          </div>
        </div>

        <div className="productPreview" aria-label="PlaylistPilot product preview">
          <div className="previewTop">
            <span>Playlist Manager</span>
            <strong>indie pop for bored indie kids</strong>
          </div>
          <div className="previewStats">
            <article><span>Followers</span><strong>16,516</strong><small>+422 this month</small></article>
            <article><span>Locked</span><strong>18</strong><small>positions protected</small></article>
            <article><span>Rotator</span><strong>6</strong><small>slots active</small></article>
          </div>
          <div className="previewRows">
            {[
              ["01", "Locked opener", "stays at position 1", "lock"],
              ["05", "Weekly discovery", "rotates from source playlist", "rotate"],
              ["18", "Older album cut", "expires in 6 days", "expiry"],
              ["42", "Backup ready", "snapshot saved before edits", "backup"],
            ].map(([pos, title, meta, tag]) => (
              <div key={pos}>
                <b>{pos}</b>
                <span><strong>{title}</strong><small>{meta}</small></span>
                <em>{tag}</em>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="trustBand">
        <span><ShieldCheck aria-hidden="true" /> Built around Spotify OAuth</span>
        <span><Check aria-hidden="true" /> Multi-account workflows</span>
        <span><Check aria-hidden="true" /> Manual and automatic backups</span>
      </section>

      <section id="features" className="section">
        <div className="sectionHeader">
          <span>Core tools</span>
          <h2>Everything needed to keep active playlists organized.</h2>
        </div>
        <div className="featureGrid">
          {features.map(({ icon: Icon, title, text }) => (
            <article key={title}>
              <Icon aria-hidden="true" />
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="workflowSection">
        <div>
          <span>Workflow</span>
          <h2>From login to automation in a few minutes.</h2>
          <p>
            PlaylistPilot is designed for repeated playlist work: select account, select playlist, edit rules,
            review upcoming changes and keep moving.
          </p>
        </div>
        <ol>
          {workflow.map((item) => <li key={item}>{item}</li>)}
        </ol>
      </section>

      <section id="pricing" className="section pricingSection">
        <div className="sectionHeader">
          <span>Plans</span>
          <h2>Start lean, scale when you manage more accounts.</h2>
        </div>
        <div className="pricingGrid">
          <article>
            <span>Economy Class</span>
            <h3>8 EUR / month</h3>
            <p>For solo curators managing one Spotify account seat.</p>
            <ul>
              <li>1 account seat</li>
              <li>Playlist manager</li>
              <li>Locks, expiry, rotator and backups</li>
            </ul>
            <a href="/app">Choose Economy</a>
          </article>
          <article className="highlightPlan">
            <span>Business Class</span>
            <h3>15 EUR / month</h3>
            <p>For operators managing multiple Spotify accounts and larger playlist portfolios.</p>
            <ul>
              <li>5 account seats</li>
              <li>Growth dashboard</li>
              <li>Priority workflow for multi-playlist operations</li>
            </ul>
            <a href="/app">Choose Business</a>
          </article>
        </div>
      </section>

      <section className="finalCta">
        <h2>Ready to pilot your playlists with less manual cleanup?</h2>
        <a className="primaryButton" href="/app">Open PlaylistPilot <ArrowRight aria-hidden="true" /></a>
      </section>

      <footer>
        <strong>PlaylistPilot</strong>
        <nav aria-label="Legal links">
          <a href="/legal/imprint">Imprint</a>
          <a href="/legal/privacy">Privacy</a>
          <a href="/legal/terms">Terms</a>
          <a href="mailto:hello@playlist-pilot.com">Contact</a>
        </nav>
      </footer>

      <style jsx>{`
        :global(body) {
          margin: 0;
          background: #0f1318;
          color: #f4f7f5;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        :global(*) {
          box-sizing: border-box;
        }
        main {
          min-height: 100vh;
          overflow-x: hidden;
          background:
            radial-gradient(circle at 78% 8%, rgba(36, 211, 102, 0.12), transparent 34%),
            linear-gradient(180deg, #11161d 0%, #0f1318 48%, #12161d 100%);
        }
        a {
          color: inherit;
          text-decoration: none;
        }
        .siteHeader {
          position: sticky;
          top: 0;
          z-index: 20;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 24px;
          padding: 20px clamp(20px, 5vw, 72px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          background: rgba(15, 19, 24, 0.84);
          backdrop-filter: blur(14px);
        }
        .brand {
          display: inline-flex;
          align-items: center;
          gap: 12px;
          font-weight: 900;
        }
        .brand img {
          width: 44px;
          height: 44px;
          border-radius: 10px;
          object-fit: cover;
        }
        nav {
          display: flex;
          align-items: center;
          gap: 18px;
          color: #aeb6c2;
          font-size: 14px;
          font-weight: 800;
        }
        nav a:hover {
          color: #24d366;
        }
        .navCta {
          padding: 10px 14px;
          border: 1px solid rgba(36, 211, 102, 0.62);
          border-radius: 8px;
          color: #24d366;
        }
        .hero {
          display: grid;
          grid-template-columns: minmax(0, 1.04fr) minmax(360px, 0.96fr);
          align-items: center;
          gap: clamp(28px, 5vw, 72px);
          min-height: calc(100vh - 86px);
          padding: clamp(54px, 7vw, 94px) clamp(20px, 5vw, 72px);
        }
        .heroCopy {
          max-width: 760px;
        }
        .eyebrow,
        .trustBand span,
        .sectionHeader span,
        .workflowSection > div span,
        .pricingGrid article > span {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          color: #24d366;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0;
        }
        .eyebrow svg,
        .trustBand svg {
          width: 16px;
          height: 16px;
        }
        h1,
        h2,
        h3,
        p {
          margin: 0;
        }
        h1 {
          margin-top: 18px;
          max-width: 760px;
          font-size: clamp(56px, 8vw, 118px);
          line-height: 0.88;
          letter-spacing: 0;
        }
        .heroCopy p {
          margin-top: 24px;
          max-width: 670px;
          color: #c5cbd3;
          font-size: clamp(18px, 2vw, 23px);
          line-height: 1.5;
        }
        .heroActions {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          margin-top: 34px;
        }
        .primaryButton,
        .secondaryButton,
        .pricingGrid a {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          min-height: 48px;
          padding: 0 18px;
          border-radius: 8px;
          font-weight: 900;
        }
        .primaryButton {
          background: #24d366;
          color: #08100c;
          border: 1px solid #24d366;
        }
        .secondaryButton {
          color: #f4f7f5;
          border: 1px solid rgba(255, 255, 255, 0.16);
          background: rgba(255, 255, 255, 0.04);
        }
        .productPreview {
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          background: rgba(20, 25, 32, 0.84);
          box-shadow: 0 24px 90px rgba(0, 0, 0, 0.38);
          overflow: hidden;
        }
        .previewTop {
          display: grid;
          gap: 6px;
          padding: 22px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          background: #1b212a;
        }
        .previewTop span,
        .previewRows small,
        .previewStats small {
          color: #aeb6c2;
        }
        .previewTop strong {
          font-size: 22px;
        }
        .previewStats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }
        .previewStats article {
          display: grid;
          gap: 5px;
          padding: 18px;
          border-right: 1px solid rgba(255, 255, 255, 0.08);
        }
        .previewStats article:last-child {
          border-right: 0;
        }
        .previewStats span {
          color: #aeb6c2;
          font-size: 12px;
          font-weight: 800;
        }
        .previewStats strong {
          font-size: 26px;
        }
        .previewRows {
          display: grid;
          padding: 10px;
        }
        .previewRows div {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr) auto;
          align-items: center;
          gap: 12px;
          padding: 12px;
          border-radius: 8px;
        }
        .previewRows div:nth-child(odd) {
          background: rgba(255, 255, 255, 0.035);
        }
        .previewRows b {
          color: #24d366;
        }
        .previewRows span {
          display: grid;
          min-width: 0;
          gap: 3px;
        }
        .previewRows em {
          border: 1px solid rgba(36, 211, 102, 0.38);
          border-radius: 999px;
          padding: 5px 9px;
          color: #24d366;
          font-size: 12px;
          font-style: normal;
          font-weight: 900;
        }
        .trustBand {
          display: flex;
          flex-wrap: wrap;
          justify-content: center;
          gap: 14px;
          padding: 20px clamp(20px, 5vw, 72px);
          border-top: 1px solid rgba(255, 255, 255, 0.08);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          background: rgba(255, 255, 255, 0.025);
        }
        .section,
        .workflowSection,
        .finalCta {
          padding: clamp(58px, 8vw, 104px) clamp(20px, 5vw, 72px);
        }
        .sectionHeader {
          display: grid;
          gap: 12px;
          max-width: 760px;
          margin-bottom: 28px;
        }
        h2 {
          font-size: clamp(32px, 4vw, 58px);
          line-height: 1;
          letter-spacing: 0;
        }
        .featureGrid,
        .pricingGrid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 14px;
        }
        .featureGrid article,
        .pricingGrid article {
          display: grid;
          align-content: start;
          gap: 14px;
          min-height: 260px;
          padding: 22px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          background: rgba(22, 27, 34, 0.82);
        }
        .featureGrid svg {
          width: 26px;
          height: 26px;
          color: #24d366;
        }
        h3 {
          font-size: 22px;
        }
        .featureGrid p,
        .workflowSection p,
        .pricingGrid p,
        .pricingGrid li {
          color: #bdc5ce;
          line-height: 1.55;
        }
        .workflowSection {
          display: grid;
          grid-template-columns: minmax(0, 0.85fr) minmax(320px, 1fr);
          gap: clamp(24px, 5vw, 70px);
          align-items: start;
          background: #141921;
          border-top: 1px solid rgba(255, 255, 255, 0.08);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }
        .workflowSection > div {
          display: grid;
          gap: 16px;
        }
        ol {
          display: grid;
          gap: 10px;
          margin: 0;
          padding: 0;
          list-style: none;
          counter-reset: steps;
        }
        ol li {
          counter-increment: steps;
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr);
          align-items: center;
          gap: 14px;
          padding: 16px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.035);
          font-weight: 900;
        }
        ol li::before {
          content: counter(steps);
          display: grid;
          place-items: center;
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: #24d366;
          color: #08100c;
        }
        .pricingGrid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
        .pricingGrid article {
          min-height: 0;
        }
        .highlightPlan {
          border-color: rgba(36, 211, 102, 0.42) !important;
          box-shadow: 0 0 0 1px rgba(36, 211, 102, 0.12) inset;
        }
        .pricingGrid ul {
          display: grid;
          gap: 8px;
          margin: 0;
          padding-left: 18px;
        }
        .pricingGrid a {
          margin-top: 6px;
          border: 1px solid rgba(36, 211, 102, 0.62);
          color: #24d366;
        }
        .finalCta {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 24px;
        }
        .finalCta h2 {
          max-width: 820px;
        }
        footer {
          display: flex;
          justify-content: space-between;
          gap: 18px;
          padding: 26px clamp(20px, 5vw, 72px);
          border-top: 1px solid rgba(255, 255, 255, 0.08);
          color: #aeb6c2;
        }
        footer strong {
          color: #f4f7f5;
        }
        @media (max-width: 980px) {
          .hero,
          .workflowSection,
          .finalCta {
            grid-template-columns: 1fr;
            align-items: stretch;
          }
          .featureGrid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
          .finalCta {
            display: grid;
          }
        }
        @media (max-width: 680px) {
          .siteHeader,
          footer {
            display: grid;
          }
          .siteHeader nav {
            width: 100%;
            justify-content: space-between;
          }
          .hero {
            padding-top: 42px;
          }
          .productPreview {
            min-width: 0;
          }
          .previewStats,
          .featureGrid,
          .pricingGrid {
            grid-template-columns: 1fr;
          }
          .previewStats article {
            border-right: 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          }
          .previewRows div {
            grid-template-columns: 34px minmax(0, 1fr);
          }
          .previewRows em {
            grid-column: 2;
            justify-self: start;
          }
        }
      `}</style>
    </main>
  );
}
