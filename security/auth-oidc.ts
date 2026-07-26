import type { AuthEnv } from './auth-env';

export type OidcDiscovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
};

export type OidcTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
};

let cachedDiscovery: { issuerUrl: string; data: OidcDiscovery } | null = null;

export async function discoverOidc(env: AuthEnv): Promise<OidcDiscovery> {
  if (cachedDiscovery?.issuerUrl === env.issuerUrl)
    return cachedDiscovery.data;

  const discoveryUrl = `${env.issuerUrl}/.well-known/openid-configuration`;
  const response = await fetch(discoveryUrl, {
    method: 'GET',
    headers: { accept: 'application/json' },
    cache: 'no-store',
  });

  if (!response.ok)
    throw new Error(`OIDC discovery failed (${response.status})`);

  const json = await response.json() as OidcDiscovery;
  if (!json.authorization_endpoint || !json.token_endpoint)
    throw new Error('OIDC discovery is missing required endpoints');

  cachedDiscovery = { issuerUrl: env.issuerUrl, data: json };
  return json;
}

export async function exchangeCodeForToken(
  discovery: OidcDiscovery,
  env: AuthEnv,
  code: string,
  redirectUri: string,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  });

  const basicCredentials = btoa(`${env.clientId}:${env.clientSecret}`);
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basicCredentials}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: params.toString(),
    cache: 'no-store',
  });

  if (!response.ok)
    throw new Error(`OIDC token exchange failed (${response.status})`);

  return await response.json() as OidcTokenResponse;
}

export async function refreshTokenGrant(
  discovery: OidcDiscovery,
  env: AuthEnv,
  refreshToken: string,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });

  const basicCredentials = btoa(`${env.clientId}:${env.clientSecret}`);
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basicCredentials}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: params.toString(),
    cache: 'no-store',
  });

  if (!response.ok)
    throw new Error(`OIDC token refresh failed (${response.status})`);

  return await response.json() as OidcTokenResponse;
}

export type OidcUserInfo = {
  sub: string;
  email?: string;
  name?: string;
  preferred_username?: string;
};

export async function fetchUserInfo(
  discovery: OidcDiscovery,
  accessToken: string,
): Promise<OidcUserInfo> {
  if (!discovery.userinfo_endpoint)
    throw new Error('OIDC userinfo endpoint not available in discovery');

  const response = await fetch(discovery.userinfo_endpoint, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${accessToken}`,
      accept: 'application/json',
    },
    cache: 'no-store',
  });

  if (!response.ok)
    throw new Error(`OIDC userinfo request failed (${response.status})`);

  const userInfo = await response.json() as OidcUserInfo;
  if (!userInfo.sub)
    throw new Error('OIDC userinfo payload is missing subject');
  return userInfo;
}
