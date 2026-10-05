const express = require('express');
const router = express.Router();
const threatController = require('../controllers/threatController');
const { authenticate, requireAdmin } = require('../middleware/auth');

router.post('/report', authenticate, threatController.reportUrl);
router.get('/stats', threatController.getThreatStats);
router.post('/verify', authenticate, requireAdmin, threatController.verifyReport);

module.exports = router;