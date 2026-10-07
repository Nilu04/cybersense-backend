const axios = require('axios');

const VT_BASE_URL = 'https://www.virustotal.com/api/v3';
const VT_TIMEOUT_MS = 15000;
const VT_POLL_ATTEMPTS = 3;
const VT_POLL_DELAY_MS = 2000;

function getApiKey() {
  return process.env.VIRUSTOTAL_API_KEY?.trim() || '';
}

function buildHeaders() {
  return {
    'x-apikey': getApiKey(),
    'Accept': 'application/json'
  };
}

function normalizeStats(stats = {}) {
  return {
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0)
  };
}

function getStatusFromStats(stats) {
  if (stats.malicious > 0) return 'malicious';
  if (stats.suspicious > 0) return 'suspicious';

  if (stats.harmless > 0 && stats.undetected === 0) {
    return 'harmless';
  }

  return 'unknown';
}

function encodeUrlId(url) {
  return Buffer.from(url, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function getUrlReport(url) {
  const urlId = encodeUrlId(url);

  return axios.get(`${VT_BASE_URL}/urls/${urlId}`, {
    headers: buildHeaders(),
    timeout: VT_TIMEOUT_MS
  });
}

async function submitUrlForAnalysis(url) {
  const body = new URLSearchParams({ url });

  return axios.post(
    `${VT_BASE_URL}/urls`,
    body.toString(),
    {
      headers: {
        ...buildHeaders(),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: VT_TIMEOUT_MS
    }
  );
}

async function getAnalysis(analysisId) {
  return axios.get(
    `${VT_BASE_URL}/analyses/${analysisId}`,
    {
      headers: buildHeaders(),
      timeout: VT_TIMEOUT_MS
    }
  );
}

async function pollAnalysis(analysisId) {
  let lastData = null;

  for (let attempt = 0; attempt < VT_POLL_ATTEMPTS; attempt += 1) {
    const response = await getAnalysis(analysisId);

    lastData = response.data?.data || null;

    const status = lastData?.attributes?.status;

    if (status === 'completed') {
      return lastData;
    }

    if (attempt < VT_POLL_ATTEMPTS - 1) {
      await sleep(VT_POLL_DELAY_MS);
    }
  }

  return lastData;
}

function buildResult(data, extra = {}) {
  const attributes = data?.attributes || {};

  const stats = normalizeStats(
    attributes.last_analysis_stats
  );

  const status = getStatusFromStats(stats);

  return {
    available: true,
    found: true,
    status,
    analysisStatus: attributes.status || 'completed',

    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected,
    timeout: stats.timeout,

    stats,

    ...extra
  };
}

/**
 * Scan a URL using VirusTotal.
 *
 * First checks whether VirusTotal already has
 * a report for the URL.
 *
 * If no report exists, submits the URL for
 * analysis and polls for the result.
 *
 * VirusTotal errors are converted into an
 * unavailable result so the main rule-based
 * scanner can continue working.
 */
async function scanUrlWithVirusTotal(url) {
  if (!getApiKey()) {
    return {
      available: false,
      found: false,
      status: 'unavailable',
      reason: 'VIRUSTOTAL_API_KEY is not configured'
    };
  }

  try {
    // Try existing VirusTotal report first
    try {
      const report = await getUrlReport(url);

      return buildResult(
        report.data?.data
      );

    } catch (error) {
      const statusCode = error.response?.status;

      // If report exists but another error occurred,
      // stop and handle it below.
      if (statusCode !== 404) {
        throw error;
      }

      // No existing report -> submit URL
      const submitted = await submitUrlForAnalysis(url);

      const analysisId =
        submitted.data?.data?.id;

      if (!analysisId) {
        return {
          available: true,
          found: false,
          status: 'pending',
          reason:
            'VirusTotal accepted the URL but did not return an analysis ID'
        };
      }

      // Poll analysis
      const analysis =
        await pollAnalysis(analysisId);

      if (!analysis?.attributes) {
        return {
          available: true,
          found: false,
          status: 'pending',
          analysisId
        };
      }

      return buildResult(
        analysis,
        { analysisId }
      );
    }

  } catch (error) {
    const statusCode =
      error.response?.status;

    const apiMessage =
      error.response?.data?.error?.message;

    const reason =
      apiMessage ||
      error.message ||
      'VirusTotal request failed';

    console.error(
      `⚠️ VirusTotal API error${
        statusCode ? ` (${statusCode})` : ''
      }: ${reason}`
    );

    return {
      available: false,
      found: false,
      status: 'unavailable',
      httpStatus: statusCode || null,
      reason
    };
  }
}

module.exports = {
  scanUrlWithVirusTotal
};