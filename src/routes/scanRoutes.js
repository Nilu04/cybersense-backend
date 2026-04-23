const express = require('express');
const { scanUrl, getScanHistory } = require('../controllers/scanController');
const { verifyApiKey } = require('../middleware/auth');

const router = express.Router();

router.post('/', verifyApiKey, scanUrl);
router.get('/history', verifyApiKey, getScanHistory);

module.exports = router;