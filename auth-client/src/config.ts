const config = {
  clientId: "demo-client",
  clientSecret: "123",
  get redirectUri() {
    return "http://localhost" + ":" + config.clientServer.port + config.clientServer.callbackPath;
  },
  authorizationServer: {
    tokenEndpoint: "http://localhost:7890/token",
    jwksUri: "http://localhost:7890/.well-known/jwks.json",
    authorizeEndpoint: "http://localhost:7890/authorize",
  },
  clientServer: {
    port: 7891,
    callbackPath: "/oauth/callback/chordstack",
    sessionCookieName: "_session",
    tokenRefreshMargin: 300, // 5 minutes in seconds
  },
  csrf: {
    csrfCookieName: "xsrf-token",
    csrfHeaderName: "x-xsrf-token",
  },
  pkce: {
    code_challenge: "JGMoIeQJqka1vqnIcPDi9YgGYWBPNQKa_ZFlqu33IIQ",
    code_challenge_method: "S256",
    code_verifier: "N0NhM0tncXhpc3h6b0ViS2w0eHRQVnFBOUtYYUtaZHc",
  },
};

export default config;
