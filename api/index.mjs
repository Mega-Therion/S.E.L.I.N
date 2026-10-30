import { handle } from "../index.mjs";

// Vercel invokes this for /api. Rewrites send / and /api/archon/* here
// without publishing index.mjs as a static page.
export default function handler(req, res) {
  return handle(req, res);
}
