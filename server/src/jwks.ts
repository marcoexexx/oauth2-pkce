import crypto from "crypto";
import jwt, { JwtPayload } from "jsonwebtoken";

export const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

export function generateToken(payload: JwtPayload) {
  return jwt.sign(payload, privateKey, { algorithm: "RS256" });
}

export function getPublicJwk() {
  const jwk = require("pem-jwk").pem2jwk(publicKey);
  return {
    ...jwk,
    kid: "1",
    alg: "RS256",
    use: "sig",
  };
}
