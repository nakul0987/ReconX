import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  ShieldAlert, 
  Search, 
  Trash2, 
  Clock, 
  MapPin, 
  RotateCcw,
  Download,
  Zap,
  Wifi,
  Globe,
  ExternalLink,
  Eye
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';

// Fix Leaflet marker icons in React
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

function MapRecenter({ center }) {
  const map = useMap();
  useEffect(() => {
    map.setView(center, 10);
  }, [center, map]);
  return null;
}

export default function App() {
  const [ipInput, setIpInput] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('manual'); // 'manual' or 'myip'

  const API_BASE = 'http://localhost:8080/api';

  useEffect(() => {
    fetchHistory();
    fetchMyIP();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setHistory(res.data || []);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    }
  };

  const fetchMyIP = async () => {
    try {
      const res = await axios.get(`${API_BASE}/my-ip`);
      if (res.data?.ip) {
        setIpInput(res.data.ip);
        handleAnalyze(res.data.ip);
      }
    } catch (err) {
      console.error('Failed to fetch public IP:', err);
    }
  };

  const handleAnalyze = async (targetIp) => {
    const queryIp = (targetIp || ipInput).trim();
    if (!queryIp) return;

    setLoading(true);
    setError('');

    try {
      const res = await axios.post(`${API_BASE}/analyze`, { ip: queryIp });
      setAnalysis(res.data);
      fetchHistory();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to complete threat analysis.');
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      await axios.delete(`${API_BASE}/history`);
      setHistory([]);
    } catch (err) {
      console.error('Failed to clear history:', err);
    }
  };

  const exportCSV = () => {
    if (!history.length) return;
    const headers = ['IP Address', 'Risk Level', 'Composite Score', 'ISP', 'City', 'Country', 'Scanned At'];
    const rows = history.map(item => [
      item.ip,
      item.threat?.riskLevel || 'Unknown',
      item.threat?.compositeRiskScore || 0,
      `"${item.network?.isp || 'Unknown'}"`,
      `"${item.location?.city || 'Unknown'}"`,
      item.location?.country || 'Unknown',
      new Date(item.scannedAt).toISOString()
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `ReconX_Logs_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getRiskBadge = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'low':
      default:
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
    }
  };

  const getCoordinates = () => {
    if (!analysis?.location?.loc) return [20.5937, 78.9629];
    const [lat, lng] = analysis.location.loc.split(',').map(Number);
    return isNaN(lat) || isNaN(lng) ? [20.5937, 78.9629] : [lat, lng];
  };

  const mapCoords = getCoordinates();

  return (
    <div className="min-h-screen bg-[#0b0c0e] text-slate-200 font-sans flex flex-col">
      
      {/* CLEAN HEADER */}
      <header className="h-16 bg-[#111317] border-b border-[#1e2228] px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center p-2 rounded-lg bg-orange-500/10 text-orange-500">
            <ShieldAlert className="w-6 h-6 stroke-[2.5]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-extrabold tracking-tight text-white">Recon<span className="text-orange-500">X</span></span>
            <span className="text-xs text-slate-400 hidden sm:inline-block">IP Intelligence & Threat Analysis</span>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 p-6 space-y-6 overflow-y-auto max-w-7xl w-full mx-auto">

        {/* MAIN GRID LAYOUT */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* LEFT MAIN COLUMN (8 COLS) */}
          <div className="lg:col-span-8 space-y-6">

            {/* SEARCH CARD */}
            <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-6 space-y-5">
              <div>
                <h1 className="text-2xl font-bold text-white">Analyze IP Address</h1>
                <p className="text-xs text-slate-400 mt-1">Get detailed information about any public IP address, including location, network details and threat reputation.</p>
              </div>

              {/* TAB TOGGLES */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <button 
                  onClick={() => setActiveTab('myip')}
                  className={`p-3 rounded-xl border text-left flex items-center gap-3 transition ${activeTab === 'myip' ? 'border-orange-500/50 bg-orange-500/5 text-white' : 'border-[#1e2228] bg-[#17191e] text-slate-400'}`}
                >
                  <div className="p-2 rounded-lg bg-orange-500/10 text-orange-500">
                    <Wifi className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold">Analyze My IP</div>
                    <div className="text-[11px] text-slate-400">Detect and analyze your current IP</div>
                  </div>
                </button>

                <button 
                  onClick={() => setActiveTab('manual')}
                  className={`p-3 rounded-xl border text-left flex items-center gap-3 transition ${activeTab === 'manual' ? 'border-orange-500/50 bg-orange-500/5 text-white' : 'border-[#1e2228] bg-[#17191e] text-slate-400'}`}
                >
                  <div className="p-2 rounded-lg bg-slate-700/30 text-slate-300">
                    <Search className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold">Enter IP Address</div>
                    <div className="text-[11px] text-slate-400">Manually enter any public IPv4 or IPv6</div>
                  </div>
                </button>
              </div>

              {/* SEARCH BAR / TRIGGER BUTTON */}
              {activeTab === 'manual' ? (
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <input 
                      type="text"
                      placeholder="Enter IPv4 or IPv6..."
                      value={ipInput}
                      onChange={(e) => setIpInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
                      className="w-full bg-[#17191e] border border-[#232730] rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-orange-500 transition"
                    />
                  </div>
                  <button 
                    onClick={() => handleAnalyze()}
                    disabled={loading}
                    className="bg-orange-500 hover:bg-orange-600 text-slate-950 font-bold px-6 py-3 rounded-xl text-sm transition flex items-center gap-2"
                  >
                    {loading ? <RotateCcw className="w-4 h-4 animate-spin" /> : 'Analyze'}
                  </button>
                </div>
              ) : (
                <button 
                  onClick={fetchMyIP}
                  className="w-full bg-orange-500 hover:bg-orange-600 text-slate-950 font-bold py-3 rounded-xl text-sm transition flex items-center justify-center gap-2"
                >
                  Analyze My IP
                </button>
              )}

              {/* PRESET CHIPS */}
              <div className="flex items-center gap-2 text-xs pt-1">
                <span className="text-slate-500 flex items-center gap-1"><Zap className="w-3 h-3 text-orange-500" /> Quick Presets:</span>
                <button onClick={() => { setIpInput('8.8.8.8'); handleAnalyze('8.8.8.8'); }} className="px-2.5 py-1 bg-[#17191e] hover:bg-[#20232a] text-slate-300 rounded-lg border border-[#232730]">Google DNS</button>
                <button onClick={() => { setIpInput('185.220.101.5'); handleAnalyze('185.220.101.5'); }} className="px-2.5 py-1 bg-red-950/20 hover:bg-red-900/30 text-red-400 rounded-lg border border-red-900/40">Tor Exit Node</button>
                <button onClick={() => { setIpInput('1.1.1.1'); handleAnalyze('1.1.1.1'); }} className="px-2.5 py-1 bg-[#17191e] hover:bg-[#20232a] text-slate-300 rounded-lg border border-[#232730]">Cloudflare</button>
              </div>
            </div>

            {/* PROGRESS WORKFLOW STATUS */}
            {loading && (
              <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-8 text-center space-y-6">
                <div className="inline-block p-4 rounded-full bg-orange-500/10 text-orange-500">
                  <RotateCcw className="w-8 h-8 animate-spin" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Analyzing IP Address...</h3>
                  <p className="text-xs text-slate-400 mt-1">Please wait while we collect information from multiple sources.</p>
                </div>

                {/* Workflow Timeline */}
                <div className="grid grid-cols-4 gap-2 pt-4">
                  <div className="space-y-2">
                    <div className="h-1 bg-orange-500 rounded-full"></div>
                    <span className="text-[10px] text-slate-400 block">Validating IP</span>
                  </div>
                  <div className="space-y-2">
                    <div className="h-1 bg-orange-500 rounded-full"></div>
                    <span className="text-[10px] text-slate-400 block">Fetching network info</span>
                  </div>
                  <div className="space-y-2">
                    <div className="h-1 bg-slate-700 rounded-full"></div>
                    <span className="text-[10px] text-slate-500 block">Checking threat data</span>
                  </div>
                  <div className="space-y-2">
                    <div className="h-1 bg-slate-700 rounded-full"></div>
                    <span className="text-[10px] text-slate-500 block">Processing results</span>
                  </div>
                </div>
              </div>
            )}

            {/* RECENT SCANS TABLE CARD */}
            <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-orange-500" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">Recent Scans</h3>
                </div>
                {history.length > 0 && (
                  <div className="flex items-center gap-3">
                    <button onClick={exportCSV} className="text-xs text-slate-400 hover:text-white flex items-center gap-1 transition">
                      <Download className="w-3.5 h-3.5" /> Export
                    </button>
                    <button onClick={handleClearHistory} className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 transition">
                      <Trash2 className="w-3.5 h-3.5" /> Clear
                    </button>
                  </div>
                )}
              </div>

              {history.length === 0 ? (
                <p className="text-xs text-slate-500 text-center py-8">No previous scans found in database.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-[#17191e] text-slate-400 uppercase tracking-wider border-b border-[#232730]">
                      <tr>
                        <th className="py-3 px-3">IP Address</th>
                        <th className="py-3 px-3">Location</th>
                        <th className="py-3 px-3">Risk</th>
                        <th className="py-3 px-3">Abuse Score</th>
                        <th className="py-3 px-3">Scanned At</th>
                        <th className="py-3 px-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2228] font-mono">
                      {history.map((item) => (
                        <tr key={item._id} className="hover:bg-[#17191e] transition">
                          <td className="py-3 px-3 font-bold text-white">{item.ip}</td>
                          <td className="py-3 px-3 font-sans text-slate-300">{item.location?.city || 'Unknown'}, {item.location?.country || ''}</td>
                          <td className="py-3 px-3">
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${getRiskBadge(item.threat?.riskLevel)}`}>
                              {(item.threat?.riskLevel || 'LOW').toUpperCase()}
                            </span>
                          </td>
                          <td className="py-3 px-3">{item.threat?.abuseConfidenceScore || 0}%</td>
                          <td className="py-3 px-3 font-sans text-slate-400">
                            {new Date(item.scannedAt).toLocaleTimeString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </td>
                          <td className="py-3 px-3 text-right">
                            <button 
                              onClick={() => { setIpInput(item.ip); handleAnalyze(item.ip); }}
                              className="p-1 rounded bg-[#1f232b] hover:bg-orange-500/20 hover:text-orange-400 text-slate-400 transition"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

          </div>

          {/* RIGHT SIDEBAR COLUMN (4 COLS) */}
          <div className="lg:col-span-4 space-y-6">

            {/* DETECTED TARGET / THREAT SUMMARY CARD */}
            <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e2228]">
                <div className="flex items-center gap-2">
                  <Wifi className="w-4 h-4 text-orange-500" />
                  <div>
                    <div className="text-[11px] text-slate-400">Target IP</div>
                    <div className="text-sm font-bold text-white font-mono">{analysis?.ip || '49.36.82.174'}</div>
                  </div>
                </div>
                <button onClick={() => handleAnalyze()} className="bg-orange-500 hover:bg-orange-600 text-slate-950 font-bold px-3 py-1.5 rounded-lg text-xs transition">
                  Re-analyze
                </button>
              </div>

              {/* THREAT SCORE METER */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-orange-500" />
                  <span className="text-xs font-bold text-white">Threat Summary</span>
                </div>
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${getRiskBadge(analysis?.threat?.riskLevel || 'Low')}`}>
                  {analysis?.threat?.riskLevel || 'Low Risk'}
                </span>
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="text-center p-3 rounded-xl bg-[#17191e] border border-[#232730] flex-1 mr-3">
                  <div className="text-3xl font-extrabold text-white font-mono">{analysis?.threat?.compositeRiskScore || 12}</div>
                  <div className="text-[10px] text-slate-400 uppercase mt-0.5">/100 Risk Score</div>
                </div>

                <div className="flex-1 space-y-2 text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>Total Reports:</span>
                    <span className="text-white font-bold">{analysis?.threat?.totalReports || 0}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Abuse Score:</span>
                    <span className="text-white font-bold">{analysis?.threat?.abuseConfidenceScore || 0}%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* LOCATION & MAP EMBED CARD */}
            <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <MapPin className="w-4 h-4 text-orange-500" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-white">Location Details</h3>
                </div>
                <span className="text-xs text-orange-500 hover:underline cursor-pointer flex items-center gap-1">
                  View on Map <ExternalLink className="w-3 h-3" />
                </span>
              </div>

              {/* MAP CONTAINER */}
              <div className="h-40 rounded-xl overflow-hidden border border-[#232730] relative">
                <MapContainer center={mapCoords} zoom={9} scrollWheelZoom={false} className="h-full w-full">
                  <TileLayer
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    attribution='&copy; OpenStreetMap'
                  />
                  <Marker position={mapCoords}>
                    <Popup>{analysis?.ip} - {analysis?.location?.city}</Popup>
                  </Marker>
                  <MapRecenter center={mapCoords} />
                </MapContainer>
              </div>

              {/* LOCATION KEY-VALUE LIST */}
              <div className="space-y-2 text-xs pt-1 font-mono">
                <div className="flex justify-between py-1 border-b border-[#1e2228]">
                  <span className="text-slate-400 font-sans">Country:</span>
                  <span className="text-white font-bold">{analysis?.location?.country || 'India'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1e2228]">
                  <span className="text-slate-400 font-sans">Region:</span>
                  <span className="text-white">{analysis?.location?.region || 'Rajasthan'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1e2228]">
                  <span className="text-slate-400 font-sans">City:</span>
                  <span className="text-white">{analysis?.location?.city || 'Jaipur'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1e2228]">
                  <span className="text-slate-400 font-sans">Timezone:</span>
                  <span className="text-white">{analysis?.location?.timezone || 'Asia/Kolkata'}</span>
                </div>
              </div>
            </div>

            {/* NETWORK INFORMATION CARD */}
            <div className="bg-[#121418] border border-[#1e2228] rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-[#1e2228]">
                <Globe className="w-4 h-4 text-orange-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">Network Information</h3>
              </div>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400 font-sans">ISP:</span>
                  <span className="text-white font-bold truncate max-w-[180px]">{analysis?.network?.isp || 'Jio Platforms Limited'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400 font-sans">ASN:</span>
                  <span className="text-white">{analysis?.network?.asn || 'AS55836'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400 font-sans">Domain:</span>
                  <span className="text-orange-400">{analysis?.network?.domain || 'jio.com'}</span>
                </div>
              </div>
            </div>

          </div>

        </div>

      </main>

    </div>
  );
}
