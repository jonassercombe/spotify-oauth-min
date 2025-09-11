export default async function handler(req, res) {
  return res.status(200).json({
    SUPABASE_URL: !!process.env.SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY: !!process.env.SUPABASE_SERVICE_ROLE_KEY
  });
}
export const config = { runtime: "nodejs18.x" };
