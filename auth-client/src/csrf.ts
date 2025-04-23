import crypto from "crypto";

const CSRF_SECRET = "super-csrf-secret";

export const generateCSRFToken = (): { token: string; signedToken: string } => {
  const token = crypto.randomBytes(32).toString("hex");
  const signedToken = crypto.createHmac("sha256", CSRF_SECRET)
    .update(token)
    .digest("hex");

  return { token, signedToken };
};

export const validateCSRFSignature = (token: string, signedToken: string): boolean => {
  const expectedSignedToken = crypto.createHmac("sha256", CSRF_SECRET)
    .update(token)
    .digest("hex");
  return expectedSignedToken === signedToken;
};
