import jwt from "jsonwebtoken";
import { JwksClient } from "jwks-rsa";
import config from "./config";

export interface TokenSet {
  access_token: string;
  refresh_token: string;
  expires_at: number; // timestamp in seconds
  token_type: string;
}

const jwksClientInstance = new JwksClient({
  jwksUri: config.authorizationServer.jwksUri,
});

export async function getSigningKey(kid: string) {
  return new Promise<jwt.Secret>((resolve, reject) => {
    jwksClientInstance.getSigningKey(kid, (err, key) => {
      if (err || !key) return reject(err);
      const signingKey = key.getPublicKey();
      resolve(signingKey);
    });
  });
}

export async function verifyAccessToken(token: string): Promise<jwt.JwtPayload> {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header.kid) {
    throw new Error("Invalid token");
  }

  const signingKey = await getSigningKey(decoded.header.kid);
  return jwt.verify(token, signingKey, { algorithms: ["RS256"] }) as jwt.JwtPayload;
}
