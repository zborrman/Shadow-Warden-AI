// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://shadow-warden-ai.com',
  integrations: [
    sitemap({
      // vercel.json sets trailingSlash: false, so `/x/` answers 308 -> `/x`.
      // Every URL in the sitemap carried the slash, i.e. every entry was a
      // redirect. Emit the canonical form (the layouts' rel=canonical already
      // strips it); the site root keeps its slash.
      serialize(item) {
        const u = new URL(item.url);
        if (u.pathname.length > 1 && u.pathname.endsWith('/')) {
          u.pathname = u.pathname.slice(0, -1);
          item.url = u.toString();
        }
        return item;
      },
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
