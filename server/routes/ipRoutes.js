const express = require('express');
const router = express.Router();
const axios = require('axios');
const ipaddr = require('ipaddr.js');
const ScanHistory = require('../models/ScanHistory');

/**
 * Helper: Validate IP and block private/reserved address ranges
 */
const validateAndCheckPrivate = (ip) => {
  if (!ipaddr.isValid(ip)) {
    return { valid: false, reason: 'Invalid IP address format.' };
  }

  const parsed = ipaddr.parse(ip);
  const range = parsed.range();

  // Block internal and non-routable IP ranges
  const forbidden = [
    'loopback',
    'private',
    'carrierGradeNat',
    'broadcast',
    'multicast',
    'linkLocal',
    'uniqueLocal',
    'unspecified',
  ];

  if (forbidden.includes(range)) {
    return {
      valid: false,
      reason: `Scan rejected: ${ip} is a private or reserved network address (${range}).`,
    };
  }

  return {
    valid: true,
    version: parsed.kind() === 'ipv6' ? 'IPv6' : 'IPv4',
  };
};

/**
 * Helper: Calculate composite risk score and operational risk level
 */
const calculateRiskLevel = (abuseScore, usageType, reports) => {
  let score = abuseScore * 0.7; // AbuseIPDB weight (70%)

  // High-risk usage types (Anonymizers / Hosting)
  const highRiskTypes = [
    'Data Center/Web Hosting/Transit',
    'Tor Exit Node',
    'VPN',
    'Commercial',
  ];
  if (highRiskTypes.includes(usageType)) score += 15;

  // Report frequency booster
  if (reports > 10) score += 15;

  const finalScore = Math.min(Math.round(score), 100);

  let level = 'Low';
  if (finalScore >= 76) level = 'Critical';
  else if (finalScore >= 46) level = 'High';
  else if (finalScore >= 16) level = 'Medium';

  return { finalScore, level };
};

// ==========================================
// ROUTES
// ==========================================

/**
 * @route   POST /api/analyze
 * @desc    Analyze a public IP address using IPInfo & AbuseIPDB
 */
router.post('/analyze', async (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({ error: 'IP address is required.' });
    }

    // 1. Sanitize & Validate IP
    const check = validateAndCheckPrivate(ip.trim());
    if (!check.valid) {
      return res.status(400).json({ error: check.reason });
    }

    const cleanIp = ip.trim();

    // 2. Fetch from IPInfo and AbuseIPDB concurrently
    const ipinfoUrl = `https://ipinfo.io/${cleanIp}?token=${process.env.IPINFO_TOKEN}`;
    const abuseUrl = `https://api.abuseipdb.com/api/v2/check`;

    const [ipinfoRes, abuseRes] = await Promise.all([
      axios.get(ipinfoUrl).catch((err) => ({ data: {} })),
      axios
        .get(abuseUrl, {
          headers: {
            Key: process.env.ABUSEIPDB_KEY,
            Accept: 'application/json',
          },
          params: { ipAddress: cleanIp, maxAgeInDays: '90', verbose: 'true' },
        })
        .catch((err) => ({ data: { data: {} } })),
    ]);

    const geoData = ipinfoRes.data || {};
    const abuseData = abuseRes.data?.data || {};

    // 3. Calculate Threat Matrix
    const abuseScore = abuseData.abuseConfidenceScore || 0;
    const usageType = abuseData.usageType || 'Unknown';
    const totalReports = abuseData.totalReports || 0;

    const { finalScore, level } = calculateRiskLevel(
      abuseScore,
      usageType,
      totalReports
    );

    // 4. Construct Structured Response Data
    const resultData = {
      ip: cleanIp,
      ipVersion: check.version,
      location: {
        city: geoData.city || 'Unknown',
        region: geoData.region || 'Unknown',
        country: geoData.country || 'Unknown',
        loc: geoData.loc || '0,0',
        timezone: geoData.timezone || 'UTC',
      },
      network: {
        asn: geoData.org ? geoData.org.split(' ')[0] : 'N/A',
        isp: abuseData.isp || geoData.org || 'Unknown',
        org: geoData.org || 'Unknown',
        hostname: geoData.hostname || abuseData.domain || 'N/A',
      },
      threat: {
        abuseConfidenceScore: abuseScore,
        totalReports: totalReports,
        lastReportedAt: abuseData.lastReportedAt || null,
        usageType: usageType,
        compositeRiskScore: finalScore,
        riskLevel: level,
      },
      scannedAt: new Date(),
    };

    // 5. Save to MongoDB
    const savedRecord = await ScanHistory.create(resultData);

    return res.status(200).json(savedRecord);
  } catch (error) {
    console.error('[Analyze Error]', error.message);
    return res
      .status(500)
      .json({ error: 'Server error while conducting IP analysis.' });
  }
});

/**
 * @route   GET /api/my-ip
 * @desc    Get the caller's current public IP address
 */
router.get('/my-ip', (req, res) => {
  let clientIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    '1.1.1.1';

  // Format IPv6 loopback / mapped IPv4
  clientIp = clientIp.replace('::ffff:', '').trim();
  if (clientIp === '::1' || clientIp === '127.0.0.1') {
    clientIp = '8.8.8.8'; // Fallback for local dev testing
  }

  return res.json({ ip: clientIp });
});

/**
 * @route   GET /api/history
 * @desc    Get recent IP scan history (latest 10)
 */
router.get('/history', async (req, res) => {
  try {
    const history = await ScanHistory.find()
      .sort({ scannedAt: -1 })
      .limit(10);
    return res.json(history);
  } catch (error) {
    console.error('[History Get Error]', error.message);
    return res.status(500).json({ error: 'Failed to retrieve scan history.' });
  }
});

/**
 * @route   DELETE /api/history
 * @desc    Clear all scan history logs
 */
router.delete('/history', async (req, res) => {
  try {
    await ScanHistory.deleteMany({});
    return res.json({ message: 'All scan history logs cleared successfully.' });
  } catch (error) {
    console.error('[History Delete Error]', error.message);
    return res.status(500).json({ error: 'Failed to clear scan history.' });
  }
});

module.exports = router;