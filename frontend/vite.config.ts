import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { resolveApiBase } from './src/services/apiBase';
import deployment from './vercel.json';

export default defineConfig(({ mode }) => {
  const envDir = fileURLToPath(new URL('..', import.meta.url));
  const env = { ...loadEnv(mode, envDir, ''), ...process.env };
  const base = resolveApiBase(env.VITE_API_BASE_URL, env.VERCEL === '1');
  const apiOrigin = base === '/api' ? '' : new URL(base).origin;
  const csp: Plugin = {
    name: 'sentinelflow-production-csp',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: {
            'http-equiv': 'Content-Security-Policy',
            content: [
              "default-src 'self'",
              "script-src 'self'",
              "style-src 'self' 'unsafe-inline'",
              `connect-src 'self'${apiOrigin ? ` ${apiOrigin}` : ''}`,
              "img-src 'self' data:",
              "font-src 'self'",
              "object-src 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
          injectTo: 'head-prepend',
        },
      ];
    },
  };
  return {
    envDir,
    plugins: [react(), csp],
    server: {
      host: '127.0.0.1',
      port: Number(env.SENTINEL_FRONTEND_PORT || env.PORT || 5173),
      strictPort: true,
      proxy: {
        '/api': {
          target: `http://127.0.0.1:${env.SENTINEL_BACKEND_PORT || 8765}`,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api(?=\/|$)/, ''),
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      strictPort: true,
      proxy: {},
      headers: Object.fromEntries(
        deployment.headers[0].headers.map(({ key, value }) => [key, value]),
      ),
    },
    test: {
      environment: 'jsdom',
      setupFiles: ['./tests/setup.ts'],
      include: ['tests/**/*.test.{ts,tsx}'],
      restoreMocks: true,
      clearMocks: true,
      unstubGlobals: true,
    },
  };
});
