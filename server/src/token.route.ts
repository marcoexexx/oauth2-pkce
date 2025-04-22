import { Router } from "express";
import { clients } from "./db";
import { FakeRedis } from "./fakeRedis";
import jwt, { JwtPayload } from "jsonwebtoken";
import { v4 as uuid4 } from "uuid";
import { checkCodeChallengeVerifier } from "./pkce";
import crypto from 'crypto'

const JWT_SECRET = "super+secret+key"

const router: Router = Router()

function validateClientAuthorize(authHeader: string | undefined, redirectUri: string) {
  const [tokenType, token] = authHeader?.split(" ") ?? [];

  if (tokenType !== "Basic" || !token) {
    return false;
  }

  const credentials = Buffer.from(token, "base64").toString("utf-8");
  const [client_id, client_secret] = credentials.split(":")

  const client = clients.get(client_id as string);

  if (!client || client_secret !== client.client_secret || !client.redirect_uris.includes(redirectUri)) {
    return false;
  }

  return true;
}

router.get("/token", async (req, res) => {
  const { grant_type, redirect_uri, code, code_verifier } = req.query;

  if (grant_type !== "authorization_code") {
    res.status(400).send("invalid_request")
    return;
  }

  const authCode = FakeRedis.getInstance().get<any>(code as string);
  const isValidClient = validateClientAuthorize(req.headers.authorization, redirect_uri as string);

  if (!isValidClient) {
    res.status(401).send("invalid_client")
    return;
  }

  FakeRedis.getInstance().remove(code as string);

  if (authCode.redirect_uri !== redirect_uri) {
    res.status(401).send("invalid_redirect")
    return;
  }

  // CHEK PKCE
  if (!await checkCodeChallengeVerifier(code_verifier as string, authCode.code_challenge, authCode.code_challenge_method)) {
    res.status(401).send("invalid_pkce")
    return;
  }

  const access_token = jwt.sign(
    {
      iss: "http://localhost:7890",
      aud: "http://localhost:7891",
      exp: Math.floor(Date.now() / 1000) + (60 * 15),
      iat: Math.floor(Date.now() / 1000),
      client_id: authCode.client_id,
      nonce: uuid4(), // TODO: nonce
      jti: uuid4(),
    } as JwtPayload,
    JWT_SECRET,
    {
      algorithm: "HS256"
    }
  )

  const refresh_token = crypto.randomBytes(32).toString("hex")

  res.status(200).json({ access_token, refresh_token })
})

export default router;
