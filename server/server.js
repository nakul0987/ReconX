require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./db');
const ipRoutes = require('./routes/ipRoutes');

const app = express();
const PORT = process.env.PORT || 8080;

// Connect Database
connectDB();

// Express Middleware
app.use(cors());
app.use(express.json());

// API Routes
app.use('/api', ipRoutes);

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'ReconX API Engine Running' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`[ReconX Backend] Server listening on http://localhost:${PORT}`);
});