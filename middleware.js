// Vercel Edge Middleware
export default function middleware(request) {
  const url = new URL(request.url);

  // F8: Allow GET, HEAD, and OPTIONS through
  if (
    request.method !== 'GET' &&
    request.method !== 'HEAD' &&
    request.method !== 'OPTIONS'
  ) {
    return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Allow': 'GET, HEAD, OPTIONS'
      }
    });
  }

  // Health check
  if (url.pathname === '/healthz' || url.pathname === '/health') {
    return new Response(JSON.stringify({ status: 'ok', source: 'edge' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }

  // F17: /badge returns minimal info, no internal feature names
  if (url.pathname === '/badge' || url.pathname === '/info') {
    return new Response(JSON.stringify({
      proxy: 'bandwidth-hero',
      version: '2.0'
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }

  return undefined;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
