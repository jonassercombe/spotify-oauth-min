export default async function handler(req, res) {
  try {
    const { bubble_user_id, label = "", return_to = "" } = req.query;
    if (!bubble_user_id) return res.status(400).send("Missing bubble_user_id");
    const stateObj = { bubble_user_id, label, return_to, nonce: Math.random().toString(36).slice(2) };
    const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");
    const scope = [
      "playlist-read-private",
      "playlist-modify-private",
      "playlist-modify-public"
    ].join(" ");
    const url =
      "https://accounts.spotify.com/authorize" +
      `?client_id=${encodeURIComponent(process.env.SPOTIFY_CLIENT_ID)}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(process.env.SPOTIFY_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scope)}` +
      `&state=${encodeURIComponent(state)}`;
    res.redirect(url);
  } catch (e) {
    console.error(e);
    res.status(500).send("start error");
  }
}
