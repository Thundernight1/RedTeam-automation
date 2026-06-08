import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import {
  Play,
  Pause,
  Shield,
  Clock,
  CheckCircle,
  XCircle,
  Settings,
  Download,
  Eye,
  Filter,
  Plus
} from 'lucide-react';
import { getStatusColor, getSeverityColor } from '../utils/jobUIHelpers';

interface ScanJob {
  id: string;
  programId: string;
  programName: string;
  type: 'port' | 'web' | 'vulnerability' | 'full';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  startTime: string;
  endTime?: string;
  targets: string[];
  profile: string;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  results: Array<{
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    target: string;
    description: string;
    confidence: number;
    cve?: string;
  }>;
}

interface ScanProfile {
  id: string;
  name: string;
  type: 'port' | 'web' | 'vulnerability' | 'full';
  description: string;
  tools: string[];
  settings: Record<string, unknown>;
}

export const Scanning: React.FC = () => {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<string>('');
  const [targets, setTargets] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  const scanProfiles: ScanProfile[] = [
    {
      id: '1',
      name: 'Port Scan',
      type: 'port',
      description: 'Basic port scanning with service detection',
      tools: ['nmap', 'masscan'],
      settings: { ports: '1-1000', timing: 'T4' }
    },
    {
      id: '2',
      name: 'Web Application',
      type: 'web',
      description: 'Web application security testing',
      tools: ['nuclei', 'zap', 'nikto'],
      settings: { depth: 3, timeout: 30 }
    },
    {
      id: '3',
      name: 'Vulnerability Assessment',
      type: 'vulnerability',
      description: 'Comprehensive vulnerability scanning',
      tools: ['nuclei', 'nmap', 'testssl'],
      settings: { severity: 'medium+', templates: 'all' }
    },
    {
      id: '4',
      name: 'Full Security Audit',
      type: 'full',
      description: 'Complete security assessment',
      tools: ['nmap', 'nuclei', 'zap', 'testssl', 'nikto'],
      settings: { comprehensive: true, timeout: 60 }
    }
  ];

  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    // Fetch scan jobs from Python gateway via Express bridge
    fetchScanJobs();
    // Poll for updates every 10 seconds
    const interval = setInterval(fetchScanJobs, 10000);
    return () => {
      abortControllerRef.current?.abort();
      clearInterval(interval);
    };
  }, []);

  const fetchScanJobs = useCallback(async () => {
    try {
      abortControllerRef.current?.abort();
      abortControllerRef.current = new AbortController();
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/scan/jobs', {
        headers: { Authorization: `Bearer ${token}` },
        signal: abortControllerRef.current.signal
      } as any);
      if (response.data) {
        setJobs(response.data as ScanJob[]);
      }
    } catch (error) {
      if ((error as Error).name === 'AbortError') {
        return;
      }
      console.error('Failed to fetch scan jobs:', error);
    }
  }, []);

  const handleStartScan = async () => {
    if (!selectedProfile || !targets) {
      alert('Please select a scan profile and enter targets');
      return;
    }

    const profile = scanProfiles.find(p => p.id === selectedProfile);
    if (!profile) return;

    const targetsList = targets.split('\n').filter((t: string) => t.trim());

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/scan/start', {
        targets: targetsList,
        profile: profile.name,
        intensity: 'normal'
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (response.status === 201 || response.status === 200) {
        console.log('Scan started:', response.data);
        fetchScanJobs();
      }
    } catch (error: unknown) {
      console.error('Failed to start scan:', error);
      const errorMsg = ((error as { response?: { data?: { error?: string } } })?.response?.data?.error) || 'Unknown error';
      alert(`Failed to start scan: ${errorMsg}`);
    }

    setIsNewScanOpen(false);
    setTargets('');
    setSelectedProfile('');
  };

  const handlePauseJob = async () => {
    alert("Pause/Resume is currently only available for local agents.");
  };

  const handleResumeJob = async () => {
    alert("Pause/Resume is currently only available for local agents.");
  };

  const handleStopJob = async (jobId: string) => {
    if (window.confirm('Are you sure you want to abort this scan mission?')) {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.post(`/api/scan/abort/${jobId}`, {}, {
           headers: { Authorization: `Bearer ${token}` }
        });
        const responseData = response.data as { status?: string; success?: boolean };
        if (responseData.status === 'aborted' || responseData.success) {
          fetchScanJobs();
        }
      } catch (_error) {
        console.error('Failed to stop job:', _error);
      }
    }
  };

  const filteredResults = (results: ScanJob['results']) => {
    if (filterSeverity === 'all') return results;
    return results.filter((result) => result.severity === filterSeverity);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Vulnerability Scanning</h1>
          <p className="text-gray-600 mt-1">Scan targets for security vulnerabilities</p>
        </div>
        <Button onClick={() => setIsNewScanOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          New Scan
        </Button>
      </div>

      {/* New Scan Modal */}
      {isNewScanOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Configure Vulnerability Scan</h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Scan Profile</label>
                <select
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select a profile</option>
                  {scanProfiles.map(profile => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} - {profile.description}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Targets (one per line)</label>
                <textarea
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  rows={4}
                  placeholder="app.example.com&#10;api.example.com&#10;admin.example.com"
                />
              </div>

              {selectedProfile && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Selected Tools</label>
                  <div className="flex flex-wrap gap-1">
                    {scanProfiles.find(p => p.id === selectedProfile)?.tools.map(tool => (
                      <Badge key={tool} variant="secondary" className="text-xs">
                        {tool}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" onClick={() => setIsNewScanOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleStartScan}>
                Start Scan
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Jobs List */}
      <div className="space-y-4">
        {jobs.map((job) => (
          <Card key={job.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-full ${getStatusColor(job.status)}`}>
                    {job.status === 'running' && <Play className="h-4 w-4" />}
                    {job.status === 'completed' && <CheckCircle className="h-4 w-4" />}
                    {job.status === 'failed' && <XCircle className="h-4 w-4" />}
                    {job.status === 'pending' && <Clock className="h-4 w-4" />}
                  </div>
                  <div>
                    <CardTitle className="text-lg">{job.programName}</CardTitle>
                    <CardDescription className="flex items-center mt-1">
                      <Shield className="h-4 w-4 mr-1" />
                      {job.profile}
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge className={getStatusColor(job.status)}>
                    {job.status.toUpperCase()}
                  </Badge>
                  {job.status === 'running' && (
                    <div className="flex space-x-1">
                      <Button size="sm" variant="outline" onClick={() => handlePauseJob()}>
                        <Pause className="h-3 w-3" />
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => handleStopJob(job.id)}>
                        <XCircle className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                  {job.status === 'paused' && (
                    <Button size="sm" variant="outline" onClick={() => handleResumeJob()}>
                      <Play className="h-3 w-3" />
                    </Button>
                  )}
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => setSelectedJob(selectedJob === job.id ? null : job.id)}
                  >
                    <Eye className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-4">
                {/* Progress */}
                <div>
                  <div className="flex justify-between text-sm text-gray-600 mb-1">
                    <span>Progress</span>
                    <span>{job.progress}%</span>
                  </div>
                  <Progress value={job.progress} className="h-2" />
                </div>

                {/* Targets */}
                <div>
                  <div className="text-sm text-gray-600 mb-2">Targets</div>
                  <div className="flex flex-wrap gap-1">
                    {job.targets.map(target => (
                      <Badge key={target} variant="outline" className="text-xs">
                        {target}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Findings Summary */}
                <div className="grid grid-cols-5 gap-2">
                  <div className="text-center p-2 bg-red-50 rounded">
                    <div className="text-lg font-bold text-red-600">{job.findings.critical}</div>
                    <div className="text-xs text-gray-500">Critical</div>
                  </div>
                  <div className="text-center p-2 bg-orange-50 rounded">
                    <div className="text-lg font-bold text-orange-600">{job.findings.high}</div>
                    <div className="text-xs text-gray-500">High</div>
                  </div>
                  <div className="text-center p-2 bg-yellow-50 rounded">
                    <div className="text-lg font-bold text-yellow-600">{job.findings.medium}</div>
                    <div className="text-xs text-gray-500">Medium</div>
                  </div>
                  <div className="text-center p-2 bg-blue-50 rounded">
                    <div className="text-lg font-bold text-blue-600">{job.findings.low}</div>
                    <div className="text-xs text-gray-500">Low</div>
                  </div>
                  <div className="text-center p-2 bg-gray-50 rounded">
                    <div className="text-lg font-bold text-gray-600">{job.findings.info}</div>
                    <div className="text-xs text-gray-500">Info</div>
                  </div>
                </div>

                {/* Detailed View */}
                {selectedJob === job.id && (
                  <div className="border-t pt-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium">Scan Results</h4>
                      <div className="flex items-center space-x-2">
                        <Filter className="h-4 w-4 text-gray-500" />
                        <select
                          value={filterSeverity}
                          onChange={(e) => setFilterSeverity(e.target.value)}
                          className="text-sm border border-gray-300 rounded px-2 py-1"
                        >
                          <option value="all">All Severities</option>
                          <option value="critical">Critical</option>
                          <option value="high">High</option>
                          <option value="medium">Medium</option>
                          <option value="low">Low</option>
                          <option value="info">Info</option>
                        </select>
                      </div>
                    </div>
                    
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {filteredResults(job.results).map((result) => (
                        <div key={result.id} className="border rounded-lg p-3">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-1">
                                <Badge className={getSeverityColor(result.severity)}>
                                  {result.severity.toUpperCase()}
                                </Badge>
                                {result.cve && (
                                  <Badge variant="outline" className="text-xs">
                                    {result.cve}
                                  </Badge>
                                )}
                                <Badge variant="outline" className="text-xs">
                                  {result.confidence}% confidence
                                </Badge>
                              </div>
                              <h5 className="font-medium text-sm">{result.title}</h5>
                              <p className="text-xs text-gray-600 mt-1">{result.description}</p>
                              <p className="text-xs text-gray-500 mt-1">Target: {result.target}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                    
                    <div className="flex justify-end space-x-2 mt-3">
                      <Button size="sm" variant="outline">
                        <Download className="h-3 w-3 mr-1" />
                        Export Report
                      </Button>
                      <Button size="sm" variant="outline">
                        <Settings className="h-3 w-3 mr-1" />
                        Configure
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};