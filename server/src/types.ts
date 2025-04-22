export interface Client {
  client_id: string;
  client_name: string;
  client_secret: string;
  redirect_uris: string[];
}

export interface AuthCode {
  client_id: string;
  redirect_uri: string;
  state: string | undefined;
  user_id: string;
  email: string;
  role: string;
  nonce?: string;
  expires_at: number;
}
