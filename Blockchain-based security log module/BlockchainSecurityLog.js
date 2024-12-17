import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Hash, ShieldCheck, AlertTriangle, Download, Upload } from 'lucide-react';
import * as jose from 'jose';

// Enhanced Cryptographic Utility Functions
class CryptoUtils {
  // Generate a cryptographically secure key pair
  static async generateKeyPair(): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-521'
      },
      true,
      ['sign', 'verify']
    );
  }

  // Sign log entry with private key
  static async signEntry(
    privateKey: CryptoKey, 
    entryData: string
  ): Promise<ArrayBuffer> {
    return await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-512'
      },
      privateKey,
      new TextEncoder().encode(entryData)
    );
  }

  // Verify log entry signature
  static async verifySignature(
    publicKey: CryptoKey, 
    signature: ArrayBuffer, 
    entryData: string
  ): Promise<boolean> {
    return await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-512'
      },
      publicKey,
      signature,
      new TextEncoder().encode(entryData)
    );
  }

  // Advanced hash function using SHA-512
  static async calculateHash(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

// Enhanced Security Log Entry Interface
interface SecurityLogEntry {
  id: string;
  timestamp: number;
  event: string;
  severity: 'low' | 'medium' | 'high';
  previousHash: string;
  hash: string;
  signature?: string;
  signedBy?: string; // Public key identifier
}

// Backend Logging Service (Simulated)
class LoggingService {
  static async sendLogToBackend(entry: SecurityLogEntry): Promise<boolean> {
    try {
      const response = await fetch('/api/security-logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(entry)
      });
      return response.ok;
    } catch (error) {
      console.error('Backend logging failed:', error);
      return false;
    }
  }

  static async fetchRemoteLogs(): Promise<SecurityLogEntry[]> {
    try {
      const response = await fetch('/api/security-logs');
      if (!response.ok) throw new Error('Failed to fetch logs');
      return await response.json();
    } catch (error) {
      console.error('Fetching remote logs failed:', error);
      return [];
    }
  }
}

// Persistent Storage Utility
class StorageManager {
  private static DB_NAME = 'SecurityLogDB';
  private static DB_VERSION = 1;

  // Open IndexedDB connection
  static async openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (!db.objectStoreNames.contains('logs')) {
          db.createObjectStore('logs', { keyPath: 'id' });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  // Save logs to IndexedDB
  static async saveLogs(logs: SecurityLogEntry[]): Promise<void> {
    const db = await this.openDB();
    const transaction = db.transaction(['logs'], 'readwrite');
    const store = transaction.objectStore('logs');

    return new Promise((resolve, reject) => {
      logs.forEach(log => store.put(log));
      
      transaction.oncomplete = () => {
        db.close();
        resolve();
      };
      transaction.onerror = () => {
        db.close();
        reject(new Error('Failed to save logs'));
      };
    });
  }

  // Retrieve logs from IndexedDB
  static async retrieveLogs(): Promise<SecurityLogEntry[]> {
    const db = await this.openDB();
    const transaction = db.transaction(['logs'], 'readonly');
    const store = transaction.objectStore('logs');

    return new Promise((resolve, reject) => {
      const request = store.getAll();
      
      request.onsuccess = () => {
        db.close();
        resolve(request.result);
      };
      
      request.onerror = () => {
        db.close();
        reject(new Error('Failed to retrieve logs'));
      };
    });
  }
}

// Enhanced Blockchain Security Log Component
const BlockchainSecurityLog: React.FC = () => {
  const [securityLogs, setSecurityLogs] = useState<SecurityLogEntry[]>([]);
  const [isChainValid, setIsChainValid] = useState<boolean | null>(null);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);

  // Initialize component with key generation and log retrieval
  useEffect(() => {
    const initializeComponent = async () => {
      // Generate cryptographic key pair
      const generatedKeyPair = await CryptoUtils.generateKeyPair();
      setKeyPair(generatedKeyPair);

      // Attempt to retrieve logs from IndexedDB
      try {
        const storedLogs = await StorageManager.retrieveLogs();
        if (storedLogs.length > 0) {
          setSecurityLogs(storedLogs);
          await validateSecurityChain(storedLogs);
        } else {
          // If no stored logs, generate initial logs
          await addLogEntry('System Initialized', 'low');
        }
      } catch (error) {
        console.error('Log retrieval failed:', error);
        await addLogEntry('System Initialized', 'low');
      }
    };

    initializeComponent();
  }, []);

  // Add a new security log entry with enhanced security
  const addLogEntry = async (
    event: string, 
    severity: 'low' | 'medium' | 'high'
  ): Promise<void> => {
    if (!keyPair) return;

    const previousEntry = securityLogs[securityLogs.length - 1];
    const newEntry: SecurityLogEntry = {
      id: `log-${Date.now()}`,
      timestamp: Date.now(),
      event,
      severity,
      previousHash: previousEntry ? previousEntry.hash : '0'.repeat(128),
      hash: '', // Will be calculated
    };

    // Calculate hash for the new entry
    newEntry.hash = await CryptoUtils.calculateHash(
      JSON.stringify({
        id: newEntry.id,
        timestamp: newEntry.timestamp,
        event: newEntry.event,
        severity: newEntry.severity,
        previousHash: newEntry.previousHash
      })
    );

    // Sign the entry
    const signatureBuffer = await CryptoUtils.signEntry(
      keyPair.privateKey, 
      newEntry.hash
    );
    newEntry.signature = Array.from(new Uint8Array(signatureBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Export public key for verification
    const exportedPublicKey = await crypto.subtle.exportKey(
      'spki', 
      keyPair.publicKey
    );
    newEntry.signedBy = Array.from(new Uint8Array(exportedPublicKey))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Update logs
    const updatedLogs = [...securityLogs, newEntry];
    setSecurityLogs(updatedLogs);

    // Persist logs to IndexedDB
    await StorageManager.saveLogs(updatedLogs);

    // Validate chain
    await validateSecurityChain(updatedLogs);

    // Send to backend
    await LoggingService.sendLogToBackend(newEntry);
  };

  // Validate the entire security log chain
  const validateSecurityChain = async (logs: SecurityLogEntry[]) => {
    if (logs.length === 0) {
      setIsChainValid(true);
      return;
    }

    let isValid = true;
    for (let i = 1; i < logs.length; i++) {
      const currentEntry = logs[i];
      const previousEntry = logs[i - 1];

      // Verify previous hash
      if (currentEntry.previousHash !== previousEntry.hash) {
        isValid = false;
        break;
      }

      // Recalculate and verify current entry's hash
      const reconstructedHash = await CryptoUtils.calculateHash(
        JSON.stringify({
          id: currentEntry.id,
          timestamp: currentEntry.timestamp,
          event: currentEntry.event,
          severity: currentEntry.severity,
          previousHash: currentEntry.previousHash
        })
      );

      if (reconstructedHash !== currentEntry.hash) {
        isValid = false;
        break;
      }
    }

    setIsChainValid(isValid);
  };

  // Export logs to JSON file
  const exportLogs = () => {
    const jsonLogs = JSON.stringify(securityLogs, null, 2);
    const blob = new Blob([jsonLogs], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-logs-${new Date().toISOString()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Import logs from JSON file
  const importLogs = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const importedLogs: SecurityLogEntry[] = JSON.parse(text);
      
      // Validate imported logs
      await validateSecurityChain(importedLogs);
      
      // Update state and persist
      setSecurityLogs(importedLogs);
      await StorageManager.saveLogs(importedLogs);
    } catch (error) {
      console.error('Log import failed:', error);
      alert('Failed to import logs. Please check the file format.');
    }
  };

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center">
          <ShieldCheck className="mr-2" /> Blockchain-Based Security Log
        </CardTitle>
        <div className="flex space-x-2">
          <Button 
            onClick={exportLogs} 
            variant="outline"
            className="flex items-center"
          >
            <Download className="mr-2 h-4 w-4" /> Export
          </Button>
          <label className="cursor-pointer">
            <input 
              type="file" 
              accept=".json" 
              onChange={importLogs} 
              className="hidden" 
            />
            <Button 
              as="span" 
              variant="outline" 
              className="flex items-center"
            >
              <Upload className="mr-2 h-4 w-4" /> Import
            </Button>
          </label>
        </div>
      </CardHeader>
      <CardContent>
        {/* Chain Integrity Indicator */}
        <div className="mb-4 flex items-center">
          {isChainValid === true && (
            <div className="flex items-center text-green-600">
              <ShieldCheck className="mr-2" /> 
              Chain Integrity Verified
            </div>
          )}
          {isChainValid === false && (
            <div className="flex items-center text-red-600">
              <AlertTriangle className="mr-2" /> 
              Chain Integrity Compromised
            </div>
          )}
        </div>

        {/* Log Entries Table */}
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gray-100">
                <th className="p-2 border">ID</th>
                <th className="p-2 border">Timestamp</th>
                <th className="p-2 border">Event</th>
                <th className="p-2 border">Severity</th>
                <th className="p-2 border">Signature</th>
              </tr>
            </thead>
            <tbody>
              {securityLogs.map((log) => (
                <tr key={log.id} 
                    className={`
                      ${log.severity === 'low' ? 'bg-green-50' : 
                        log.severity === 'medium' ? 'bg-yellow-50' : 
                        'bg-red-50'}
                    `}>
                  <td className="p-2 border">{log.id}</td>
                  <td className="p-2 border">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="p-2 border">{log.event}</td>
                  <td className="p-2 border text-center">
                    {log.severity.toUpperCase()}
                  </td>
                  <td className="p-2 border text-xs">
                    {log.signature 
                      ? `${log.signature.substring(0, 12)}...` 
                      : 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Action Buttons */}
        <div className="mt-4 flex space-x-2">
          <Button 
            onClick={() => addLogEntry('User Action Logged', 'low')}
            className="bg-blue-500 hover:bg-blue-600"
          >
            Log User Action
          </Button>
          <Button 
            onClick={() => addLogEntry('Potential Anomaly', 'medium')}
            className="bg-yellow-500 hover:bg-yellow-600"
          >
            Log Anomaly
          </Button>
          <Button 
            onClick={() => addLogEntry('Critical Security Event', 'high')}
            className="bg-red-500 hover:bg-red-600"
          >
            Log Critical Event
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

export default BlockchainSecurityLog;
