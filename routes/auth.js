const { Router } = require('express');
const { v4 } = require('uuid');
const logger = require('../lib/logger');

const { saveAuth, findOneAuth } = require('../stores/store');

const router = Router();

// creates a new token to access the registry
router.post('/token', async (req, res) => {
  let newToken = '';

  const isAdmin = req.body.isAdmin || false;
  const permissions = req.body.permissions || {};

  let exists = 'exists';

  while (exists) {
    newToken = v4();
    // eslint-disable-next-line no-await-in-loop
    exists = await findOneAuth({ token: newToken });
  }

  await saveAuth({ token: newToken, isAdmin, permissions });

  return res.render('auth/create', { token: newToken, isAdmin, permissions });
});

module.exports = router;
