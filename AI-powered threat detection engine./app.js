import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  Shield, 
  Crosshair, 
  Activity, 
  Server, 
  Database 
} from 'lucide-react';

// Mock threat detection service
const mockThreatDetectionService = {
  scanNetwork: async () => {
    // Simulate network scanning
    await new Promise(resolve => setTimeout(resolve, 1500));
    return {
      status: Math.random() > 0.3 ? 'SECURE' : 'THREAT_DETECTED',
      threats: [
        { 
          id: 'threat-001', 
          type: 'Suspicious IP', 
          severity: 'HIGH', 
          source: '192.168.1.100',
          details: 'Potential brute force attempt detected'
        },
        { 
          id: 'threat-002', 
          type: 'Unusual Traffic Pattern', 
          severity: 'MEDIUM', 
          source: '10.0.0.55',
          details: 'Abnormal data transfer volume detected'
        }
      ]
    };
  },
  analyzeLogs: async () => {
    // Simulate log analysis
    await new Promise(resolve => setTimeout(resolve, 1000));
    return {
      anomalies: [
        {
          timestamp: new Date().toISOString(),
          description: 'Unauthorized access attempt',
          risk: 'HIGH'
        }
      ]
    };
  }
};

const ThreatDetectionEngine = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [networkStatus, setNetworkStatus] = useState(null);
  const [threats, setThreats] = useState([]);
  const [logAnomalies, setLogAnomalies] = useState([]);

  const performThreatDetection = async () => {
    setIsScanning(true);
    setNetworkStatus(null);
    setThreats([]);
    setLogAnomalies([]);

    try {
      // Simulate parallel threat detection processes
      const [networkScan, logAnalysis] = await Promise.all([
        mockThreatDetectionService.scanNetwork(),
        mockThreatDetectionService.analyzeLogs()
      ]);

      setNetworkStatus(networkScan.status);
      setThreats(networkScan.threats);
      setLogAnomalies(logAnalysis.anomalies);
    } catch (error) {
      console.error('Threat detection failed', error);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="bg-gray-900 text-white min-h-screen p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6 flex items-center">
          <Shield className="mr-3 text-blue-500" /> AI Threat Detection Engine
        </h1>

        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <button 
            onClick={performThreatDetection}
            disabled={isScanning}
            className={`w-full py-3 rounded-lg flex items-center justify-center ${
              isScanning 
                ? 'bg-gray-600 cursor-not-allowed' 
                : 'bg-blue-600 hover:bg-blue-700 transition-colors'
            }`}
          >
            {isScanning ? (
              <>
                <Activity className="mr-2 animate-spin" />
                Scanning Network...
              </>
            ) : (
              <>
                <Crosshair className="mr-2" />
                Perform Threat Detection
              </>
            )}
          </button>
        </div>

        {networkStatus && (
          <div className="mb-6">
            <h2 className="text-2xl font-semibold mb-4">
              Network Status
            </h2>
            <div className={`p-4 rounded-lg ${
              networkStatus === 'SECURE' 
                ? 'bg-green-800' 
                : 'bg-red-800'
            }`}>
              <div className="flex items-center">
                {networkStatus === 'SECURE' ? (
                  <Shield className="mr-2 text-green-400" />
                ) : (
                  <AlertTriangle className="mr-2 text-red-400" />
                )}
                <span className="font-bold">
                  {networkStatus === 'SECURE' 
                    ? 'Network Secure' 
                    : 'Threats Detected'}
                </span>
              </div>
            </div>
          </div>
        )}

        {threats.length > 0 && (
          <div className="mb-6">
            <h2 className="text-2xl font-semibold mb-4">
              Detected Threats
            </h2>
            {threats.map(threat => (
              <div 
                key={threat.id} 
                className={`p-4 rounded-lg mb-3 ${
                  threat.severity === 'HIGH' 
                    ? 'bg-red-900' 
                    : 'bg-yellow-900'
                }`}
              >
                <div className="flex justify-between items-center">
                  <div>
                    <div className="font-bold">{threat.type}</div>
                    <div className="text-sm text-gray-300">
                      Source: {threat.source}
                    </div>
                    <div className="mt-2 text-sm">
                      {threat.details}
                    </div>
                  </div>
                  <div className={`font-bold ${
                    threat.severity === 'HIGH' 
                      ? 'text-red-400' 
                      : 'text-yellow-400'
                  }`}>
                    {threat.severity}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {logAnomalies.length > 0 && (
          <div>
            <h2 className="text-2xl font-semibold mb-4">
              Log Anomalies
            </h2>
            {logAnomalies.map((anomaly, index) => (
              <div 
                key={index} 
                className="bg-gray-800 p-4 rounded-lg mb-3"
              >
                <div className="flex justify-between items-center">
                  <div>
                    <div className="font-bold text-red-400">
                      {anomaly.description}
                    </div>
                    <div className="text-sm text-gray-300">
                      Timestamp: {new Date(anomaly.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className={`font-bold ${
                    anomaly.risk === 'HIGH' 
                      ? 'text-red-500' 
                      : 'text-yellow-500'
                  }`}>
                    {anomaly.risk} Risk
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatDetectionEngine;
