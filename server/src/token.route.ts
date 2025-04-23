import { Router } from "express";
import { clients } from "./db";
import { FakeRedis } from "./fakeRedis";
import jwt, { JwtPayload } from "jsonwebtoken";
import { v4 as uuid4 } from "uuid";
import { checkCodeChallengeVerifier } from "./pkce";
import crypto from 'crypto'
import { getPublicJwk, privateKey } from "./jwks";

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

router.post("/token", async (req, res) => {
  const { grant_type, redirect_uri, code, code_verifier, refresh_token } = req.body;

  const isValidClient = validateClientAuthorize(req.headers.authorization, redirect_uri as string);

  if (!isValidClient) {
    res.status(401).send("invalid_client")
    return;
  }

  if (grant_type === "authorization_code") {
    const authCode = FakeRedis.getInstance().get<any>(code as string);

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

    const userId = "user123" // INFO: for demo
    // const expires_in = 60 * 15;
    const expires_in = 10

    const access_token = jwt.sign(
      {
        sub: userId,
        iss: "http://localhost:7890",
        aud: "http://localhost:7891",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + expires_in,
        client_id: authCode.client_id,
        nonce: uuid4(), // TODO: nonce
        scope: "read write", // TODO: scope for api, req.body.scope
        jti: uuid4(),
      } as JwtPayload,
      privateKey,
      {
        keyid: "1",
        algorithm: "RS256"
      }
    )

    const refresh_token = crypto.randomBytes(32).toString("hex")

    FakeRedis.getInstance().set(`refresh_token:${refresh_token}`, {
      sub: userId,
      client_id: authCode.client_id,
      expirse_in: 60 * 60 * 24 * 7
    })

    res.status(200).json({ access_token, refresh_token, expires_in, token_type: "Bearer" })
  } else if (grant_type === "refresh_token") {
    const token = FakeRedis.getInstance().get<any>(`refresh_token:${refresh_token}`)
    if (!token) {
      res.status(401).json({ error: 'invalid_grant' })
      return;
    }

    // const expires_in = 60 * 15;
    const expires_in = 10

    const access_token = jwt.sign(
      {
        sub: token.sub,
        iss: "http://localhost:7890",
        aud: "http://localhost:7891",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (expires_in), // 15m
        client_id: token.client_id,
        nonce: uuid4(), // TODO: nonce
        scope: "read write", // TODO: scope for api, req.body.scope
        jti: uuid4(),
      } as JwtPayload,
      privateKey,
      {
        keyid: "1",
        algorithm: "RS256"
      }
    )

    const new_refresh_token = crypto.randomBytes(32).toString("hex")

    FakeRedis.getInstance().set<any>(`refresh_token:${new_refresh_token}`, { // INFO: replace new refresh_token, revoke old token
      sub: token.sub,
      client_id: token.client_id,
      expirse_in: 60 * 60 * 24 * 7
    })

    res.status(200).json({ 
      access_token,
      refresh_token: new_refresh_token,
      token_type: "Bearer",
      expires_in,
    })
  }
})

router.get("/.well-known/jwks.json", (_req, res) => {
  res.status(200).json({
    keys: [getPublicJwk()]
  })
})

export default router;
