import { expect, test } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

test.describe('Portail IT — layout plein écran', () => {
  test('le shell remplit la largeur du viewport', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await gotoOk(page, '/it/', 1500);

    const metrics = await page.evaluate(() => {
      const wrap = document.querySelector('.fp-it-wrap');
      const main = document.querySelector('.cc-it-main');
      const body = document.body;
      if (!wrap || !main) return null;
      const wr = wrap.getBoundingClientRect();
      const mr = main.getBoundingClientRect();
      const br = body.getBoundingClientRect();
      const cs = getComputedStyle(wrap);
      return {
        viewportW: window.innerWidth,
        wrapW: wr.width,
        mainW: mr.width,
        bodyW: br.width,
        maxWidth: cs.maxWidth,
        marginLeft: cs.marginLeft,
        paddingLeft: cs.paddingLeft,
      };
    });

    expect(metrics, 'structure IT').not.toBeNull();
    if (!metrics) return;

    expect(metrics.maxWidth).toBe('none');
    expect(metrics.wrapW).toBeGreaterThan(metrics.viewportW * 0.95);
    expect(metrics.mainW).toBeGreaterThan(400);

    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, '/it/ layout');
  });

  test('hauteur shell ≈ viewport (header + body + footer)', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await gotoOk(page, '/it/#it-dashboard', 1200);

    const heights = await page.evaluate(() => {
      const wrap = document.querySelector('.fp-it-wrap');
      if (!wrap) return null;
      const r = wrap.getBoundingClientRect();
      return { wrapH: r.height, viewportH: window.innerHeight };
    });

    expect(heights).not.toBeNull();
    if (!heights) return;
    expect(heights.wrapH).toBeGreaterThan(heights.viewportH * 0.92);
    expect(heights.wrapH).toBeLessThanOrEqual(heights.viewportH + 2);
  });
});
