// Renders a report's navy header (label, title, subtitle and logo) as a PNG.
// Outlook's dark mode recolours HTML backgrounds and text but never images, so the
// header is sent as an image to keep it navy with white text in both modes.
// Usage: node tools/render_header.js <out.png> "<label>" "<title html>" "<subtitle>"
// Run from the repo root. Needs Playwright with Chromium.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const [out, label, title, subtitle] = process.argv.slice(2);
  const logo = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo-email-navy.png')).toString('base64');
  const html = `<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600&family=Libre+Franklin:wght@400;500&display=block" rel="stylesheet">
<style>
  body{margin:0;background:#071320}
  .h{width:820px;box-sizing:border-box;background:#071320;padding:30px 40px 30px;position:relative}
  .lab{font:400 11px 'Libre Franklin',Arial,sans-serif;letter-spacing:4px;text-transform:uppercase;color:#ACB1B6}
  .logo{position:absolute;right:40px;top:28px;width:170px;height:45px}
  .t{margin-top:30px;font:600 40px/1.02 'Barlow Condensed','Arial Narrow',sans-serif;text-transform:uppercase;color:#F4F2EA;letter-spacing:.3px}
  .t span{color:#FE9026}
  .s{margin-top:12px;font:400 14px 'Libre Franklin',Arial,sans-serif;color:#F4F2EA}
</style></head><body><div class="h" id="h">
<div class="lab">${label}</div><img class="logo" src="data:image/png;base64,${logo}">
<div class="t">${title}</div><div class="s">${subtitle}</div></div></body></html>`;
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  const b = await chromium.launch(proxy ? { proxy: { server: proxy } } : {});
  const p = await b.newPage({ deviceScaleFactor: 2, ignoreHTTPSErrors: true });
  await p.setContent(html, { waitUntil: 'networkidle' });
  await p.evaluate(() => document.fonts.ready);
  await (await p.$('#h')).screenshot({ path: out });
  await b.close();
})();
