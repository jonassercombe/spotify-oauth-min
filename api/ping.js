export default async function handler(req, res) {
  return res.status(200).send("ok");
}

// Erzwinge Node-Runtime, falls Vercel Edge defaultet:
export const config = { runtime: "nodejs18.x" };
