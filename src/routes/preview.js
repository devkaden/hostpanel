'use strict';

/**
 * The preview proxy: a site's own pages, served back through the panel.
 *
 * Mounted before the sign-in check rather than behind it, which looks wrong
 * and is not. The frame is sandboxed without allow-same-origin, so the
 * document inside it has an opaque origin, and a browser treats everything
 * that document asks for as cross-site: the SameSite=Lax session cookie is
 * simply not sent. Behind requireAuth, the page loaded and then every image
 * and stylesheet in it came back as a redirect to the sign-in form - a preview
 * with the text and none of the pictures.
 *
 * What stands in for the cookie is the token in the path. It is minted when
 * the site page is rendered, for someone who has already passed the sign-in
 * check and who is allowed to see that site, and it expires. A page's URLs all
 * carry it without being asked to: the <base> tag and the rewriting in
 * src/preview.js put it in front of every path the page resolves.
 *
 * What it grants is narrow: looking at one site, which is a website - usually
 * one already published on the internet. It is not a panel session, it cannot
 * reach any other site, and it says nothing about who minted it.
 */

const express = require('express');

const sites = require('../sites');
const preview = require('../preview');
const { wrap } = require('../middleware');

const router = express.Router();

const EXPIRED_PAGE =
  '<!doctype html><meta charset="utf-8">' +
  '<body style="font:15px system-ui;padding:2rem;color:#444">' +
  '<h2 style="margin:0 0 .5rem">This preview has expired</h2>' +
  '<p>Reload the site page to start a new one.</p>';

/*
 * Every method and every path under the prefix, because a page is not just its
 * HTML: its stylesheets, images, fonts and form posts all have to come through
 * the same door or the render is wrong.
 */
router.all(
  // Express 4 route syntax: a trailing * captures the rest of the path. The
  // bare form is matched too, so /preview/<token> works as well as
  // /preview/<token>/.
  ['/preview/:token', '/preview/:token/*'],
  wrap(async (req, res) => {
    const entry = preview.resolveToken(req.params.token);
    if (!entry) return res.status(410).type('html').send(EXPIRED_PAGE);

    const site = sites.getSite(entry.siteId);
    if (!site) return res.status(404).type('text').send('That site no longer exists.');
    if (!site.port) return res.status(409).type('text').send('This site has no port yet.');

    const base = `/preview/${req.params.token}/`;
    // Everything after the prefix, query string included, is the site's path.
    const rest = req.originalUrl.slice(base.length - 1) || '/';

    return preview.proxy(req, res, {
      port: site.port,
      base,
      upstreamPath: rest.startsWith('/') ? rest : `/${rest}`,
    });
  })
);

module.exports = router;
