import Head from "next/head";
import { useEffect, useRef, useState } from "react";

const MESSAGE_TYPE = "PLAYLISTPILOT_SPOTIFY_PLAYER";
const validTrackId = (value) => /^[A-Za-z0-9]{22}$/.test(String(value || ""));

export default function ExtensionPlayer() {
  const mountRef = useRef(null);
  const controllerRef = useRef(null);
  const pendingRef = useRef([]);
  const [status, setStatus] = useState("Loading Spotify player…");

  useEffect(() => {
    let iframeApi = null;
    let creating = false;
    const notify = (event, detail = {}) => window.parent.postMessage({ type: MESSAGE_TYPE, event, ...detail }, "*");
    const loadTrack = (controller, trackId) => {
      const uri = `spotify:track:${trackId}`;
      if (typeof controller.loadEntity === "function") controller.loadEntity(uri);
      else controller.loadUri(uri);
    };
    const apply = ({ action, trackId }) => {
      const controller = controllerRef.current;
      if (!controller) return;
      if (action === "load" && validTrackId(trackId)) loadTrack(controller, trackId);
      if (action === "play") controller.play();
      if (action === "pause") controller.pause();
      if (action === "toggle") controller.togglePlay();
      if (action === "loadAndPlay" && validTrackId(trackId)) {
        loadTrack(controller, trackId);
        window.setTimeout(() => controller.play(), 120);
      }
    };
    const create = (trackId) => {
      if (!iframeApi || creating || controllerRef.current || !mountRef.current || !validTrackId(trackId)) return;
      creating = true;
      iframeApi.createController(mountRef.current, {
        uri: `spotify:track:${trackId}`,
        width: "100%",
        height: 80,
      }, (controller) => {
        controllerRef.current = controller;
        controller.addListener("ready", () => {
          setStatus("");
          notify("ready");
          pendingRef.current.splice(0).forEach(apply);
        });
        controller.addListener("playback_started", () => notify("playing", { playing: true }));
        controller.addListener("playback_paused", () => notify("playing", { playing: false }));
        controller.addListener("playback_update", (event) => notify("playbackUpdate", {
          playing: !event?.data?.isPaused,
          position: event?.data?.position || 0,
          duration: event?.data?.duration || 0,
        }));
      });
    };
    const run = ({ action, trackId }) => {
      if (controllerRef.current) return apply({ action, trackId });
      pendingRef.current.push({ action, trackId });
      create(trackId);
    };
    const onMessage = (event) => {
      if (event.source !== window.parent || event.data?.type !== MESSAGE_TYPE) return;
      run(event.data);
    };
    window.addEventListener("message", onMessage);
    window.onSpotifyIframeApiReady = (SpotifyIframeApi) => {
      iframeApi = SpotifyIframeApi;
      notify("bridgeReady");
      const firstTrack = pendingRef.current.find((item) => validTrackId(item.trackId))?.trackId;
      if (firstTrack) create(firstTrack);
    };
    const script = document.createElement("script");
    script.src = "https://open.spotify.com/embed/iframe-api/v1";
    script.async = true;
    script.onerror = () => {
      setStatus("Spotify player could not be loaded.");
      notify("error", { message: "Spotify player could not be loaded." });
    };
    document.body.appendChild(script);
    return () => {
      window.removeEventListener("message", onMessage);
      delete window.onSpotifyIframeApiReady;
      script.remove();
    };
  }, []);

  return (
    <>
      <Head><title>PlaylistPilot Spotify Player</title><meta name="robots" content="noindex,nofollow" /></Head>
      <main><div ref={mountRef} />{status ? <p>{status}</p> : null}</main>
      <style jsx global>{`
        html, body { margin: 0; min-height: 100%; background: #101318; color: #aeb6c2; font: 12px/1.4 Inter, system-ui, sans-serif; }
        main { min-height: 80px; }
        iframe { display: block; width: 100%; border: 0; border-radius: 12px; }
        p { display: grid; min-height: 80px; margin: 0; place-items: center; padding: 10px; text-align: center; }
      `}</style>
    </>
  );
}
