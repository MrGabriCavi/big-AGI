import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { createSignedJson, randomUrlSafe, verifySignedJson } from './auth-crypto';
import { readAuthEnv } from './auth-env';
import { discoverOidc, exchangeCodeForToken, fetchUserInfo, refreshTokenGrant } from './auth-oidc';
import { syncAuthenticatedUser } from './auth-user-sync';

type AuthSession = {
  sub: string;
  email?: string;
  name?: string;
  refreshToken?: string;
  iat: number;
  exp: number;
};

type AuthState = {
  nonce: string;
  returnTo: string;
  issuedAt: number;
};

const SESSION_COOKIE = 'bigagi_auth_session';
const OAUTH_STATE_COOKIE = 'bigagi_auth_state';
const LOGIN_PATH = '/auth/login';
const CALLBACK_PATH = '/auth/callback';
const LOGOUT_PATH = '/auth/logout';
const DEFAULT_HOME_PATH = '/';

function nowEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isPublicPath(pathname: string): boolean {
  return pathname.startsWith('/_next/')
    || pathname.startsWith('/images/')
    || pathname.startsWith('/icons/')
    || pathname.startsWith('/sounds/')
    || pathname.startsWith('/workers/')
    || pathname === '/favicon.ico';
}

function isAuthPath(pathname: string): boolean {
  return pathname === LOGIN_PATH || pathname === CALLBACK_PATH || pathname === LOGOUT_PATH;
}

function asSafeRelativePath(path: string | null): string {
  if (!path)
    return DEFAULT_HOME_PATH;
  if (!path.startsWith('/'))
    return DEFAULT_HOME_PATH;
  if (path.startsWith('//'))
    return DEFAULT_HOME_PATH;
  return path;
}

function canUseInsecureHttpDev(request: NextRequest, allowInsecureHttpDev: boolean): boolean {
  return allowInsecureHttpDev
    && process.env.NODE_ENV !== 'production'
    && request.nextUrl.protocol === 'http:';
}

function shouldUseSecureCookies(request: NextRequest, allowInsecureHttpDev: boolean): boolean {
  return !canUseInsecureHttpDev(request, allowInsecureHttpDev);
}

function resolveRedirectUri(request: NextRequest): string {
  const env = readAuthEnv();
  if (canUseInsecureHttpDev(request, env.allowInsecureHttpDev))
    return env.devRedirectUri || `${request.nextUrl.origin}${CALLBACK_PATH}`;
  return env.redirectUri;
}

function redirectToLogin(request: NextRequest): NextResponse {
  const loginUrl = new URL(LOGIN_PATH, request.url);
  loginUrl.searchParams.set('rd', `${request.nextUrl.pathname}${request.nextUrl.search}`);
  return NextResponse.redirect(loginUrl);
}

function clearAuthCookies(response: NextResponse): void {
  response.cookies.set({
    name: SESSION_COOKIE,
    value: '',
    path: '/',
    maxAge: 0,
  });
  response.cookies.set({
    name: OAUTH_STATE_COOKIE,
    value: '',
    path: '/',
    maxAge: 0,
  });
}

async function validateSession(request: NextRequest, cookieSecret: string): Promise<AuthSession | null> {
  const rawCookie = request.cookies.get(SESSION_COOKIE)?.value;
  if (!rawCookie)
    return null;

  const session = await verifySignedJson<AuthSession>(rawCookie, cookieSecret);
  if (!session?.sub)
    return null;

  return session;
}

function shouldRefreshSession(session: AuthSession, refreshAheadSeconds: number): boolean {
  const now = nowEpochSeconds();
  return session.exp <= now + refreshAheadSeconds;
}

async function createRefreshedSession(currentSession: AuthSession): Promise<AuthSession | null> {
  const env = readAuthEnv();
  if (!currentSession.refreshToken)
    return null;

  const discovery = await discoverOidc(env);
  const token = await refreshTokenGrant(discovery, env, currentSession.refreshToken);

  const issuedAt = nowEpochSeconds();
  const ttlSeconds = typeof token.expires_in === 'number' && token.expires_in > 0
    ? token.expires_in
    : env.sessionTtlSeconds;

  return {
    sub: currentSession.sub,
    email: currentSession.email,
    name: currentSession.name,
    refreshToken: token.refresh_token || currentSession.refreshToken,
    iat: issuedAt,
    exp: issuedAt + ttlSeconds,
  };
}

async function handleLogin(request: NextRequest): Promise<NextResponse> {
  const env = readAuthEnv();
  const discovery = await discoverOidc(env);
  const redirectUri = resolveRedirectUri(request);
  const secureCookies = shouldUseSecureCookies(request, env.allowInsecureHttpDev);

  const returnTo = asSafeRelativePath(request.nextUrl.searchParams.get('rd'));
  const nonce = randomUrlSafe(24);
  const statePayload: AuthState = {
    nonce,
    returnTo,
    issuedAt: nowEpochSeconds(),
  };

  const signedState = await createSignedJson(statePayload, env.cookieSecret);

  const authorizeUrl = new URL(discovery.authorization_endpoint);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', env.clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('scope', env.scopes);
  authorizeUrl.searchParams.set('state', nonce);

  const response = NextResponse.redirect(authorizeUrl);
  response.cookies.set({
    name: OAUTH_STATE_COOKIE,
    value: signedState,
    httpOnly: true,
    secure: secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60,
  });

  return response;
}

async function handleCallback(request: NextRequest): Promise<NextResponse> {
  const env = readAuthEnv();
  const redirectUri = resolveRedirectUri(request);
  const secureCookies = shouldUseSecureCookies(request, env.allowInsecureHttpDev);
  const stateFromQuery = request.nextUrl.searchParams.get('state');
  const code = request.nextUrl.searchParams.get('code');
  const signedState = request.cookies.get(OAUTH_STATE_COOKIE)?.value;

  if (!stateFromQuery || !code || !signedState)
    return new NextResponse('Authentication callback is invalid', { status: 400 });

  const state = await verifySignedJson<AuthState>(signedState, env.cookieSecret);
  if (!state || state.nonce !== stateFromQuery)
    return new NextResponse('Invalid OAuth state', { status: 400 });

  const discovery = await discoverOidc(env);
  const token = await exchangeCodeForToken(discovery, env, code, redirectUri);
  const userInfo = await fetchUserInfo(discovery, token.access_token);

  const issuedAt = nowEpochSeconds();
  const session: AuthSession = {
    sub: userInfo.sub,
    email: userInfo.email,
    name: userInfo.name || userInfo.preferred_username,
    refreshToken: token.refresh_token,
    iat: issuedAt,
    exp: issuedAt + (typeof token.expires_in === 'number' && token.expires_in > 0 ? token.expires_in : env.sessionTtlSeconds),
  };

  const signedSession = await createSignedJson(session, env.cookieSecret);
  const response = NextResponse.redirect(new URL(state.returnTo || DEFAULT_HOME_PATH, request.url));

  response.cookies.set({
    name: SESSION_COOKIE,
    value: signedSession,
    httpOnly: true,
    secure: secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: env.sessionTtlSeconds,
  });
  response.cookies.set({
    name: OAUTH_STATE_COOKIE,
    value: '',
    path: '/',
    maxAge: 0,
  });

  await syncAuthenticatedUser(request, {
    subject: userInfo.sub,
    email: userInfo.email,
    name: userInfo.name || userInfo.preferred_username,
  }, env.internalSyncSecret);

  return response;
}

async function handleLogout(request: NextRequest): Promise<NextResponse> {
  const env = readAuthEnv();
  const discovery = await discoverOidc(env);

  const response = NextResponse.redirect(new URL(DEFAULT_HOME_PATH, request.url));
  clearAuthCookies(response);

  if (discovery.end_session_endpoint) {
    const endSessionUrl = new URL(discovery.end_session_endpoint);
    endSessionUrl.searchParams.set(
      'post_logout_redirect_uri',
      env.postLogoutRedirectUri || new URL(DEFAULT_HOME_PATH, request.url).toString(),
    );
    return NextResponse.redirect(endSessionUrl, {
      headers: response.headers,
    });
  }

  return response;
}

export async function authMiddleware(request: NextRequest): Promise<NextResponse> {
  const env = readAuthEnv();

  if (!env.enabled)
    return NextResponse.next();

  const pathname = request.nextUrl.pathname;
  if (isPublicPath(pathname))
    return NextResponse.next();

  try {
    if (pathname === LOGIN_PATH)
      return await handleLogin(request);
    if (pathname === CALLBACK_PATH)
      return await handleCallback(request);
    if (pathname === LOGOUT_PATH)
      return await handleLogout(request);

    if (isAuthPath(pathname))
      return NextResponse.next();

    const session = await validateSession(request, env.cookieSecret);
    if (!session)
      return redirectToLogin(request);

    // Expired session without refresh token must re-authenticate.
    if (session.exp <= nowEpochSeconds() && !session.refreshToken)
      return redirectToLogin(request);

    if (shouldRefreshSession(session, env.refreshAheadSeconds) && session.refreshToken) {
      try {
        const refreshedSession = await createRefreshedSession(session);
        if (!refreshedSession)
          return redirectToLogin(request);

        const signedSession = await createSignedJson(refreshedSession, env.cookieSecret);
        const response = NextResponse.next();
        response.cookies.set({
          name: SESSION_COOKIE,
          value: signedSession,
          httpOnly: true,
          secure: shouldUseSecureCookies(request, env.allowInsecureHttpDev),
          sameSite: 'lax',
          path: '/',
          maxAge: env.sessionTtlSeconds,
        });
        return response;
      } catch (refreshError) {
        console.warn('[auth] session refresh failed', refreshError);
        const loginRedirect = redirectToLogin(request);
        clearAuthCookies(loginRedirect);
        return loginRedirect;
      }
    }

    if (session.exp <= nowEpochSeconds()) {
      const loginRedirect = redirectToLogin(request);
      clearAuthCookies(loginRedirect);
      return loginRedirect;
    }

    return NextResponse.next();
  } catch (error) {
    console.error('[auth] middleware error', error);
    return new NextResponse('Authentication error', { status: 500 });
  }
}
