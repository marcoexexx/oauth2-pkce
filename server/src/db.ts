import { Client } from "./types";

export const clients = new Map<string, Client>();

clients.set("demo-client", {
  client_id: "demo-client",
  client_name: "demo",
  client_secret: "123",
  redirect_uris: ["http://localhost:7891/oauth/callback/chordstack"]
})
