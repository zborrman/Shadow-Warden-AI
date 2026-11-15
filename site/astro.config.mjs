// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://shadow-warden-ai.com',
  // Astro 7 changed the default to 'jsx', which drops the single space between
  // inline elements that sit on separate source lines. 75 of 77 pages lost
  // spaces between adjacent links and labels under that default. `true` is the
  // Astro 6 behaviour: lossless, HTML-aware compression.
  compressHTML: true,
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
