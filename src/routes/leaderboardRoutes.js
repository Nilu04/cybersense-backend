const express = require('express');
const router = express.Router();
const leaderboardController = require('../controllers/leaderboardController');
const { authenticate } = require('../middleware/auth');

router.get('/', leaderboardController.getGlobalLeaderboard);
router.get('/rank', authenticate, leaderboardController.getUserRank);

module.exports = router;