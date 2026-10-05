const express = require('express');
const { scanUrl } = require('../controllers/scanController');
const { verifyApiKey } = require('../middleware/auth');

const router = express.Router();

router.post('/', verifyApiKey, scanUrl);

module.exports = router;