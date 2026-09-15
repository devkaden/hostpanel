'use strict';

const sites = require('./sites');
const auth = require('./auth');

/** Loads req.site from :id and enforces ownership (admins see everything). */
function loadSite(req, res, next) {
  const id = parseInt(req.params.id, 10);
  const site = Number.isInteger(id) ? sites.getSite(id) : null;
  if (!site) {
    if (auth.wantsJson(req)) return res.status(404).json({ error: 'Site not found' });
    return res.status(404).render('error', {
      title: 'Not found',
      message: 'That site does not exist.',
    });
  }
  if (!sites.canAccess(req.user, site)) {
    if (auth.wantsJson(req)) return res.status(403).json({ error: 'Access denied' });
    return res.status(403).render('error', {
      title: 'Forbidden',
      message: 'You do not have access to that site.',
    });
  }
  req.site = site;
  res.locals.site = site;
  return next();
}

/** Wraps an async handler so rejections reach the error middleware. */
function wrap(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

module.exports = { loadSite, wrap };
