const express = require('express');
const { getScanHistory } = require('../controllers/scanController');
const { verifyApiKey } = require('../middleware/auth');

const router = express.Router();

router.get('/', verifyApiKey, getScanHistory);

module.exports = router;