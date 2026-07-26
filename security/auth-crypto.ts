const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(base64Url: string): Uint8Array {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length)
    return false;
  let result = 0;
  for (let i = 0; i < a.length; i++)
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function hmacSha256(input: string, secret: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, textEncoder.encode(input));
  return bytesToBase64Url(new Uint8Array(signature));
}

export async function createSignedJson(value: unknown, secret: string): Promise<string> {
  const payload = bytesToBase64Url(textEncoder.encode(JSON.stringify(value)));
  const signature = await hmacSha256(payload, secret);
  return `${payload}.${signature}`;
}

export async function verifySignedJson<T>(signedValue: string, secret: string): Promise<T | null> {
  const [payload, signature] = signedValue.split('.');
  if (!payload || !signature)
    return null;

  const expectedSignature = await hmacSha256(payload, secret);
  if (!constantTimeEquals(expectedSignature, signature))
    return null;

  try {
    const jsonText = textDecoder.decode(base64UrlToBytes(payload));
    return JSON.parse(jsonText) as T;
  } catch {
    return null;
  }
}

export function randomUrlSafe(size = 32): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}
