import type { NextRequest } from 'next/server';
import { authMiddleware } from './security/middleware-auth';


// noinspection JSUnusedGlobalSymbols
export async function middleware(request: NextRequest) {
  return authMiddleware(request);
}

export const config = {
  matcher: [
    // Auth endpoints
    '/auth/:path*',
    // Include root
    '/',
    // Include pages
    '/(call|index|news|personas|link)(.*)',
    // Include API routes
    '/api(.*)',
  ],
};
