import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    target: 'es2022',
    // Source maps let anyone verify that the deployed bundle matches this
    // repository. For a tool whose security claim is "the client does the
    // encryption", shipping an unreadable minified blob and asking users to take
    // that on faith undercuts the entire point.
    sourcemap: true,
    rollupOptions: {
      output: {
        // Split the two heavy, rarely-changing dependency groups into their own
        // chunks so an application-code change does not invalidate the cached
        // lattice and highlighting code. A function rather than a map because
        // Vite 8's bundler only accepts the callback form.
        manualChunks(id: string): string | undefined {
          if (id.includes('@noble')) return 'crypto-primitives';
          if (id.includes('highlight.js')) return 'highlight';
          if (id.includes('dompurify') || id.includes('marked')) return 'markdown';
          return undefined;
        },
      },
    },
  },
  worker: { format: 'es' },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8787' },
  },
});
