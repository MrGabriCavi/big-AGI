export type AuthEnv = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  devRedirectUri?: string;
  allowInsecureHttpDev: boolean;
  postLogoutRedirectUri?: string;
  cookieSecret: string;
  sessionTtlSeconds: number;
  refreshAheadSeconds: number;
  internalSyncSecret?: string;
  scopes: string;
};

function required(name: string): string {
  const value = process.env[name];
  if (!value)
    throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function asBool(value: string | undefined, defaultValue: boolean): boolean {
  if (!value)
    return defaultValue;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function asInt(value: string | undefined, defaultValue: number): number {
  if (!value)
    return defaultValue;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0)
    throw new Error('AUTH_SESSION_TTL_SECONDS must be a positive integer');
  return parsed;
}

export function readAuthEnv(): AuthEnv {
  const enabled = asBool(process.env.AUTH_ENABLED, false);
  if (!enabled)
    return {
      enabled,
      issuerUrl: '',
      clientId: '',
      clientSecret: '',
      redirectUri: '',
      allowInsecureHttpDev: false,
      cookieSecret: '',
      sessionTtlSeconds: 1,
      refreshAheadSeconds: 60,
      scopes: 'openid profile email',
    };

  const issuerUrl = required('AUTH_ISSUER_URL').replace(/\/$/, '');
  if (!issuerUrl.startsWith('https://'))
    throw new Error('AUTH_ISSUER_URL must use https://');

  return {
    enabled,
    issuerUrl,
    clientId: required('AUTH_CLIENT_ID'),
    clientSecret: required('AUTH_CLIENT_SECRET'),
    redirectUri: required('AUTH_REDIRECT_URI'),
    devRedirectUri: process.env.AUTH_DEV_REDIRECT_URI,
    allowInsecureHttpDev: asBool(process.env.AUTH_ALLOW_INSECURE_HTTP_DEV, false),
    postLogoutRedirectUri: process.env.AUTH_POST_LOGOUT_REDIRECT_URI,
    cookieSecret: required('AUTH_COOKIE_SECRET'),
    sessionTtlSeconds: asInt(process.env.AUTH_SESSION_TTL_SECONDS, 8 * 60 * 60),
    refreshAheadSeconds: asInt(process.env.AUTH_REFRESH_AHEAD_SECONDS, 60),
    internalSyncSecret: process.env.AUTH_INTERNAL_SYNC_SECRET,
    scopes: process.env.AUTH_SCOPES?.trim() || 'openid profile email',
  };
}
