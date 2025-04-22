export function base64UrlEncode(arrayBuffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode.apply(null, arrayBuffer as any));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function checkCodeChallengeVerifier(codeVerifier: string, challenge: string, challenge_method: string) {
  if (challenge_method !== "S256") return false;

  try {
    const encoder = new TextEncoder();
    const verifierBuffer = encoder.encode(codeVerifier);

    const hashBuffer = await crypto.subtle.digest('SHA-256', verifierBuffer);

    const hashArray = new Uint8Array(hashBuffer);
    const hashBase64Url = base64UrlEncode(hashArray);

    return hashBase64Url === challenge;
  } catch (error) {
    console.error('Error in code challenge verification:', error);
    return false;
  }
}


