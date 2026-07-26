import type { NextRequest } from 'next/server';

type SyncUserPayload = {
  subject: string;
  email?: string;
  name?: string;
};

export async function syncAuthenticatedUser(
  request: NextRequest,
  payload: SyncUserPayload,
  secret?: string,
): Promise<void> {
  try {
    const syncUrl = new URL('/api/auth/user-login', request.url);
    const response = await fetch(syncUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(secret ? { 'x-auth-sync-secret': secret } : {}),
      },
      body: JSON.stringify(payload),
      cache: 'no-store',
    });

    if (!response.ok)
      console.warn('[auth] user sync failed with status', response.status);
  } catch (error) {
    console.warn('[auth] user sync request failed', error);
  }
}
