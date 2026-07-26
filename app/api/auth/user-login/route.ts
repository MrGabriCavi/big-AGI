import { prismaDb } from '~/server/prisma/prismaDb';

export const runtime = 'nodejs';

type UserLoginBody = {
  subject?: string;
  email?: string;
  name?: string;
};

export async function POST(request: Request) {
  try {
    const expectedSecret = process.env.AUTH_INTERNAL_SYNC_SECRET;
    if (expectedSecret) {
      const providedSecret = request.headers.get('x-auth-sync-secret');
      if (providedSecret !== expectedSecret)
        return new Response('Unauthorized', { status: 401 });
    }

    const body = await request.json() as UserLoginBody;
    const subject = body.subject?.trim();

    if (!subject)
      return new Response('Missing subject', { status: 400 });

    await prismaDb.authUser.upsert({
      where: { subject },
      create: {
        subject,
        email: body.email?.trim() || null,
        name: body.name?.trim() || null,
        lastLoginAt: new Date(),
      },
      update: {
        email: body.email?.trim() || null,
        name: body.name?.trim() || null,
        lastLoginAt: new Date(),
      },
    });

    return Response.json({ ok: true });
  } catch (error) {
    console.error('[auth-user-sync] failed', error);
    return new Response('Internal error', { status: 500 });
  }
}
