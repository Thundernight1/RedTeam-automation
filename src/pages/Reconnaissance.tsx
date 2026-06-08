import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import {
  Play,
  Pause,
  RotateCcw,
  Globe,
  Clock,
  CheckCircle,
  XCircle,
  Settings,
  Download,
  Eye
} from 'lucide-react';
import { getStatusColor, getLogLevelColor } from '../utils/jobUIHelpers';

interface ReconJob {
  id: string;
  programId: string;
  programName: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  startTime: string;
  endTime?: string;
  target: string;
  tools: string[];
  results: {
    subdomains: number;
    openPorts: number;
    technologies: number;
    endpoints: number;
  };
  logs: Array<{
    timestamp: string;
    level: 'info' | 'warning' | 'error';
    message: string;
  }>;
}

interface TargetConfig {
  domain: string;
  scope: string[];
  tools: string[];
  aggressive: boolean;
  recursive: boolean;
  timeout: number;
}

export const Reconnaissance: React.FC = () => {
  const [jobs, setJobs] = useState<ReconJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [targetConfig, setTargetConfig] = useState<TargetConfig>({
    domain: '',
    scope: [],
    tools: ['amass', 'subfinder', 'httpx', 'naabu'],
    aggressive: false,
    recursive: true,
    timeout: 3600
  });

  useEffect(() => {
    // Simulate fetching recon jobs
    fetchReconJobs();
  }, []);

  const fetchReconJobs = async () => {
    try {
      const res = await axios.get('/api/recon');
      const data = (res as any).data.data || [];
      setJobs(data.map((j: any) => ({
        id: j.id,
        programId: '',
        programName: 'Manual Recon',
        target: j.target,
        status: j.status,
        progress: j.status === 'completed' ? 100 : j.status === 'running' ? 50 : j.status === 'failed' ? 25 : 0,
        startTime: j.startedAt,
        endTime: j.completedAt,
        tools: [],
        results: {
          subdomains: j.results?.subdomains?.length || 0,
          openPorts: j.results?.ports?.length || 0,
          technologies: j.results?.technologies?.length || 0,
          endpoints: j.results?.endpoints?.length || 0
        },
        logs: [{ timestamp: j.startedAt, level: 'info', message: `Recon started for ${j.target}` }]
      })));
    } catch (error) {
      console.error('Failed to fetch recon jobs:', error);
    }
  };

  const handleStartRecon = async () => {
    if (!targetConfig.domain) {
      alert('Please enter a target domain');
      return;
    }
    try {
      const res = await axios.post('/api/recon/start', {
        target: targetConfig.domain,
        type: 'full',
        modules: targetConfig.tools
      });
      const job = (res as any).data.data;
      setJobs(prev => [{
        id: job.id,
        programId: '',
        programName: 'Manual Recon',
        target: job.target,
        status: job.status,
        progress: 0,
        startTime: job.startedAt,
        tools: targetConfig.tools,
        results: { subdomains: 0, openPorts: 0, technologies: 0, endpoints: 0 },
        logs: [{ timestamp: job.startedAt, level: 'info', message: `Recon started for ${job.target}` }]
      }, ...prev]);
    } catch (error) {
      alert('Failed to start recon');
    }
    setIsConfigOpen(false);
  };

  const handlePauseJob = async (jobId: string) => {
    setJobs(prev => prev.map(job =>
      job.id === jobId
        ? { ...job, status: 'paused' }
        : job
    ));
  };

  const handleResumeJob = async (jobId: string) => {
    setJobs(prev => prev.map(job =>
      job.id === jobId
        ? { ...job, status: 'running' }
        : job
    ));
  };

  const handleStopJob = async (jobId: string) => {
    setJobs(prev => prev.map(job =>
      job.id === jobId
        ? { ...job, status: 'failed', progress: job.progress }
        : job
    ));
  };

  const handleRestartJob = async (jobId: string) => {
    setJobs(prev => prev.map(job =>
      job.id === jobId
        ? {
          ...job,
          status: 'pending',
          progress: 0,
          startTime: new Date().toISOString(),
          results: { subdomains: 0, openPorts: 0, technologies: 0, endpoints: 0 },
          logs: []
        }
        : job
    ));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reconnaissance</h1>
          <p className="text-gray-600 mt-1">Discover targets and gather information</p>
        </div>
        <Button onClick={() => setIsConfigOpen(true)}>
          <Play className="h-4 w-4 mr-2" />
          Start New Scan
        </Button>
      </div>

      {/* Target Configuration Modal */}
      {isConfigOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Configure Reconnaissance Scan</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Target Domain</label>
                <input
                  type="text"
                  value={targetConfig.domain}
                  onChange={(e) => setTargetConfig({ ...targetConfig, domain: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="example.com or *.example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Scope (one per line)</label>
                <textarea
                  value={targetConfig.scope.join('\n')}
                  onChange={(e) => setTargetConfig({ ...targetConfig, scope: e.target.value.split('\n').filter(s => s.trim()) })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  rows={3}
                  placeholder="*.example.com&#10;api.example.com&#10;app.example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Tools</label>
                <div className="grid grid-cols-2 gap-2">
                  {['amass', 'subfinder', 'httpx', 'naabu', 'wappalyzer', 'whatweb'].map(tool => (
                    <label key={tool} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={targetConfig.tools.includes(tool)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setTargetConfig({ ...targetConfig, tools: [...targetConfig.tools, tool] });
                          } else {
                            setTargetConfig({ ...targetConfig, tools: targetConfig.tools.filter(t => t !== tool) });
                          }
                        }}
                        className="mr-2"
                      />
                      <span className="text-sm">{tool}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={targetConfig.aggressive}
                    onChange={(e) => setTargetConfig({ ...targetConfig, aggressive: e.target.checked })}
                    className="mr-2"
                  />
                  <span className="text-sm">Aggressive Mode</span>
                </label>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={targetConfig.recursive}
                    onChange={(e) => setTargetConfig({ ...targetConfig, recursive: e.target.checked })}
                    className="mr-2"
                  />
                  <span className="text-sm">Recursive Scan</span>
                </label>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Timeout (seconds)</label>
                <input
                  type="number"
                  value={targetConfig.timeout}
                  onChange={(e) => setTargetConfig({ ...targetConfig, timeout: parseInt(e.target.value) })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="300"
                  max="14400"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" onClick={() => setIsConfigOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleStartRecon}>
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
                      <Globe className="h-4 w-4 mr-1" />
                      {job.target}
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge className={getStatusColor(job.status)}>
                    {job.status.toUpperCase()}
                  </Badge>
                  {job.status === 'running' && (
                    <div className="flex space-x-1">
                      <Button size="sm" variant="outline" onClick={() => handlePauseJob(job.id)}>
                        <Pause className="h-3 w-3" />
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => handleStopJob(job.id)}>
                        <XCircle className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                  {job.status === 'paused' && (
                    <Button size="sm" variant="outline" onClick={() => handleResumeJob(job.id)}>
                      <Play className="h-3 w-3" />
                    </Button>
                  )}
                  {(job.status === 'completed' || job.status === 'failed') && (
                    <Button size="sm" variant="outline" onClick={() => handleRestartJob(job.id)}>
                      <RotateCcw className="h-3 w-3" />
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

                {/* Results */}
                <div className="grid grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-lg font-bold text-blue-600">{job.results.subdomains}</div>
                    <div className="text-xs text-gray-500">Subdomains</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-green-600">{job.results.openPorts}</div>
                    <div className="text-xs text-gray-500">Open Ports</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-purple-600">{job.results.technologies}</div>
                    <div className="text-xs text-gray-500">Technologies</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-orange-600">{job.results.endpoints}</div>
                    <div className="text-xs text-gray-500">Endpoints</div>
                  </div>
                </div>

                {/* Tools */}
                <div>
                  <div className="text-sm text-gray-600 mb-2">Tools Used</div>
                  <div className="flex flex-wrap gap-1">
                    {job.tools.map(tool => (
                      <Badge key={tool} variant="secondary" className="text-xs">
                        {tool}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Detailed View */}
                {selectedJob === job.id && (
                  <div className="border-t pt-4">
                    <h4 className="font-medium mb-3">Scan Logs</h4>
                    <div className="bg-gray-50 rounded-lg p-3 max-h-64 overflow-y-auto">
                      {job.logs.map((log, index) => (
                        <div key={index} className="flex items-start space-x-2 py-1">
                          <span className={`text-xs ${getLogLevelColor(log.level)}`}>
                            [{log.level.toUpperCase()}]
                          </span>
                          <span className="text-xs text-gray-600">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </span>
                          <span className="text-sm text-gray-800 flex-1">{log.message}</span>
                        </div>
                      ))}
                    </div>

                    <div className="flex justify-end space-x-2 mt-3">
                      <Button size="sm" variant="outline">
                        <Download className="h-3 w-3 mr-1" />
                        Export Results
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
}