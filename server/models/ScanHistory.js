const mongoose = require('mongoose');

const scanHistorySchema = new mongoose.Schema(
  {
    ip: {
      type: String,
      required: true,
      index: true,
      trim: true,
    },
    ipVersion: {
      type: String,
      enum: ['IPv4', 'IPv6'],
      required: true,
    },
    location: {
      city: { type: String, default: 'Unknown' },
      region: { type: String, default: 'Unknown' },
      country: { type: String, default: 'Unknown' },
      loc: { type: String, default: '0,0' }, // "lat,lng" format for Leaflet
      timezone: { type: String, default: 'UTC' },
    },
    network: {
      asn: { type: String, default: 'N/A' },
      isp: { type: String, default: 'Unknown' },
      org: { type: String, default: 'Unknown' },
      hostname: { type: String, default: 'N/A' },
    },
    threat: {
      abuseConfidenceScore: { type: Number, default: 0 },
      totalReports: { type: Number, default: 0 },
      lastReportedAt: { type: Date, default: null },
      usageType: { type: String, default: 'Unknown' },
      compositeRiskScore: { type: Number, default: 0 },
      riskLevel: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Critical'],
        default: 'Low',
      },
    },
    scannedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('ScanHistory', scanHistorySchema);