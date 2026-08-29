// @ts-check
import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import starlight from '@astrojs/starlight';
import remarkCrateVersions from './scripts/remark-crate-versions.mjs';

const site = 'https://biandratti.github.io';
const base = '/huginn-net';

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  markdown: {
    // Astro's default `satteri()` processor doesn't run `remarkPlugins`.
    // Switch to `unified()` so our crate-version substitution plugin (and
    // Starlight's own remark plugins, which it appends automatically) run.
    processor: unified({ remarkPlugins: [remarkCrateVersions] }),
  },
  vite: {
    server: {
      watch: {
        // Avoid watching Cargo build output (huge file counts, unrelated
        // to the docs site); prevents ENOSPC from exhausting inotify watches.
        ignored: ['**/target/**'],
      },
    },
  },
  integrations: [
    starlight({
      title: 'Huginn Net',
      description:
        'Multi-Protocol Passive Network Fingerprinting for Rust: TCP, HTTP, and TLS.',
      titleDelimiter: '·',
      tagline: 'TCP · HTTP · TLS',
      logo: {
        src: './src/assets/huginn-net.png',
        alt: 'Huginn Net',
        replacesTitle: false,
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/biandratti/huginn-net',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'link',
          attrs: {
            rel: 'preconnect',
            href: 'https://fonts.googleapis.com',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'preconnect',
            href: 'https://fonts.gstatic.com',
            crossorigin: 'anonymous',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,600;1,400&display=swap',
          },
        },
      ],
      favicon: '/favicon.ico',
      lastUpdated: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 4 },
      components: {
        Footer: './src/components/StarlightSiteFooter.astro',
      },
      sidebar: [
        { label: 'Home', link: '/' },
        {
          label: 'Getting started',
          items: [
            { label: 'Overview', slug: 'docs/overview' },
            { label: 'Ecosystem', slug: 'docs/ecosystem' },
            { label: 'Matching', slug: 'docs/matching' },
            { label: 'Quick example', slug: 'docs/quick-example' },
          ],
        },
        {
          label: 'Protocols',
          items: [
            { label: 'TCP SYN and SYN+ACK packets', slug: 'docs/syn-ack-packet' },
            { label: 'TCP MTU', slug: 'docs/mtu' },
            { label: 'TCP Uptime', slug: 'docs/uptime' },
            { label: 'HTTP request and response', slug: 'docs/http' },
            { label: 'TLS', slug: 'docs/tls' },
          ],
        },
      ],
    }),
  ],
});
