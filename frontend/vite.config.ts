import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), ''), ...process.env };
  return {
    plugins: [react()],
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
