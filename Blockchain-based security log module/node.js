import express, { Request, Response } from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';

// Security Log Interface
interface SecurityLogEntry {
  id: string;
  timestamp: number;
  event: string;
  severity: 'low' | 'medium' | 'high';
  previousHash: string;
  hash: string;
  signature?: string;
  signedBy?: string;
}

class SecurityLogService {
  private static LOGS_FILE = path.join(__dirname, 'security-logs.json');

  // Retrieve all logs
  static getLogs(): SecurityLogEntry[] {
    try {
      if (!fs.existsSync(this.LOGS_FILE)) {
        return [];
      }
      const rawData = fs.readFileSync(this.LOGS_FILE, 'utf8');
      return JSON.parse(rawData);
    } catch (error) {
      console.error('Error reading logs:', error);
      return [];
    }
  }

  // Add new log entry
  static addLog(log: SecurityLogEntry): boolean {
    try {
      const existingLogs = this.getLogs();
      
      // Optional: Implement additional validation
      if (!this.validateLogEntry(log)) {
        return false;
      }

      existingLogs.push(log);
      
      fs.writeFileSync(
        this.LOGS_FILE, 
        JSON.stringify(existingLogs, null, 2), 
        'utf8'
      );
      
      return true;
    } catch (error) {
      console.error('Error adding log:', error);
      return false;
    }
  }

  // Validate log entry
  private static validateLogEntry(log: SecurityLogEntry): boolean {
    // Implement comprehensive validation
    if (!log.id || !log.event || !log.timestamp) {
      return false;
    }

    // Optional: Add signature verification
    return true;
  }
}

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/api/security-logs', (req: Request, res: Response) => {
  try {
    const logs = SecurityLogService.getLogs();
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
});

app.post('/api/security-logs', (req: Request, res: Response) => {
  try {
    const newLog = req.body;
    const success = SecurityLogService.addLog(newLog);
    
    if (success) {
      res.status(201).json({ message: 'Log added successfully' });
    } else {
      res.status(400).json({ error: 'Invalid log entry' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to add log' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Security Log Backend running on port ${PORT}`);
});

export default app;
