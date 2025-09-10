export default async function handler(req, res) {
  try {
    // --- Basic checks ---
    if (!process.env.SPOTIFY_CLIENT_ID || !process.env.SPOTIFY_REDIRECT_URI) {
      return res
        .status(500)
        .send("Server misconfigured: missing SPOTIFY_CLIENT_ID or SPOTIFY_REDIRECT_URI");
    }

    // --- Read params ---
    const { bubble_user_id, label = "", return_to = "" } = req.query;
    if (!bubble_user_id) {
      return res.status(400).send("Missing query param: bubble_user_id");
    }

    // --- Build state (base64url JSON) ---
    const stateObj = {
      bubble_user_id,
      label,
      return_to,
      nonce: Math.random().toString(36).slice(2) // simple CSRF-ish nonce
    };
    const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");

    // --- Scopes (anpassen falls nötig) ---
    const scope = [
      "playlist-read-private",
      "playlist-modify-private",
      "playlist-modify-public"
    ].join(" ");

    // --- Build Spotify authorize url ---
    // show_dialog=true erzwingt den Consent-Screen -> Spotify gibt wahrscheinlicher refresh_token zurück
    const url =
      "https://accounts.spotify.com/authorize" +
      `?client_id=${encodeURIComponent(process.env.SPOTIFY_CLIENT_ID)}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(process.env.SPOTIFY_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scope)}` +
      `&state=${encodeURIComponent(state)}` +
      `&show_dialog=true`;

    return res.redirect(url);
  } catch (e) {
    console.error("start error:", e);
    return res.status(500).send("start error");
  }
}
