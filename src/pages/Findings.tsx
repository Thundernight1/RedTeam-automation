import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import {
  Target,
  Filter,
  Search,
  Download,
  Eye,
  Edit,
  Trash2,
  Tag,
  User,
  Calendar
} from 'lucide-react';

interface Finding {
  id: string;
  programId: string;
  programName: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  status: 'submitted' | 'triaged' | 'resolved' | 'duplicate' | 'not_applicable' | 'spam';
  type: 'sql_injection' | 'xss' | 'idor' | 'xxe' | 'ssrf' | 'lfi' | 'command_injection' | 'misconfiguration' | 'information_disclosure';
  target: string;
  cve?: string;
  cvss?: number;
  remediation: string;
  impact: string;
  likelihood: string;
  risk_score: number;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  triagedBy?: string;
  triagedAt?: string;
  reporter?: string;
  evidence: Array<{
    type: 'screenshot' | 'log' | 'request' | 'response' | 'file';
    data: string;
    description: string;
  }>;
  comments: Array<{
    id: string;
    author: string;
    content: string;
    createdAt: string;
  }>;
}

interface TriageConfig {
  autoTriage: boolean;
  severityThreshold: string;
  confidenceThreshold: number;
  falsePositiveRules: string[];
  duplicateDetection: boolean;
}

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [triageConfig, setTriageConfig] = useState<TriageConfig>({
    autoTriage: true,
    severityThreshold: 'medium',
    confidenceThreshold: 70,
    falsePositiveRules: ['common_misconfigurations', 'ssl_scanner_artifacts'],
    duplicateDetection: true
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [sortBy] = useState<'severity' | 'confidence' | 'createdAt' | 'risk_score'>('severity');
  const [sortOrder] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    fetchFindings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchTerm, filterSeverity, filterStatus]);

  const fetchFindings = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/findings', {
        params: {
          search: searchTerm,
          severity: filterSeverity,
          status: filterStatus,
          page: 1, // Add pagination support later if needed
          limit: 100
        },
        headers: { Authorization: `Bearer ${token}` }
      });
      const responseData = response.data as Record<string, unknown>;
      if (responseData.success) {
        setFindings(responseData.data as Finding[]);
      }
    } catch (_error) {
      console.error("Failed to fetch findings", _error);
    }
  };

  const handleTriage = async (findingId: string, status: Finding['status']) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.patch(`/api/findings/${findingId}/status`, 
        { status },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const responseData = response.data as Record<string, unknown>;
      if (responseData.success) {
        setFindings((prev: Finding[]) => prev.map((f: Finding) =>
          f.id === findingId
            ? {
                ...f,
                status: status,
                updatedAt: new Date().toISOString()
              }
            : f
        ));
      }
    } catch (_error) {
      console.error("Failed to update finding status", _error);
    }
  };

  const handleBulkTriage = async (status: Finding['status']) => {
    // For bulk triage, we'd need a bulk update endpoint or loop through new findings
    const newFindings = findings.filter(f => f.status === 'submitted');
    for (const finding of newFindings) {
      await handleTriage(finding.id, status);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      case 'info':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'submitted':
        return 'bg-blue-100 text-blue-800';
      case 'triaged':
        return 'bg-yellow-100 text-yellow-800';
      case 'resolved':
        return 'bg-green-100 text-green-800';
      case 'not_applicable':
        return 'bg-gray-100 text-gray-800';
      case 'duplicate':
        return 'bg-purple-100 text-purple-800';
      case 'spam':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'sql_injection':
        return '🗃️';
      case 'xss':
        return '🌐';
      case 'idor':
        return '🔑';
      case 'xxe':
        return '📄';
      case 'ssrf':
        return '🌐';
      case 'lfi':
        return '📁';
      case 'command_injection':
        return '💻';
      case 'misconfiguration':
        return '⚙️';
      case 'information_disclosure':
        return '👁️';
      default:
        return '🔍';
    }
  };

  const filteredAndSortedFindings = () => {
    const filtered = findings.filter((finding: Finding) => {
      const matchesSearch = searchTerm === '' || 
        finding.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.target.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesSeverity = filterSeverity === 'all' || finding.severity === filterSeverity;
      const matchesStatus = filterStatus === 'all' || finding.status === filterStatus;
      
      return matchesSearch && matchesSeverity && matchesStatus;
    });

    return filtered.sort((a: Finding, b: Finding) => {
      let aValue, bValue;
      switch (sortBy) {
        case 'severity': {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          aValue = severityOrder[a.severity];
          bValue = severityOrder[b.severity];
          break;
        }
        case 'confidence':
          aValue = a.confidence;
          bValue = b.confidence;
          break;
        case 'createdAt':
          aValue = new Date(a.createdAt).getTime();
          bValue = new Date(b.createdAt).getTime();
          break;
        case 'risk_score':
          aValue = a.risk_score;
          bValue = b.risk_score;
          break;
        default:
          return 0;
      }
      
      return sortOrder === 'desc' ? bValue - aValue : aValue - bValue;
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Findings Management</h1>
          <p className="text-gray-600 mt-1">Review, triage, and manage security findings</p>
        </div>
        <div className="flex space-x-2">
          <Button onClick={() => handleBulkTriage('triaged')} variant="outline">
            Bulk Triage
          </Button>
          <Button onClick={async () => {
            try {
              const token = localStorage.getItem('token');
              const res = await axios.get('/api/findings/export?format=csv', {
                headers: { Authorization: `Bearer ${token}` },
                responseType: 'blob'
              });
              const url = window.URL.createObjectURL(new Blob([res.data as BlobPart]));
              const link = document.createElement('a');
              link.href = url;
              link.setAttribute('download', 'findings.csv');
              document.body.appendChild(link);
              link.click();
              link.remove();
            } catch {
              alert('Export failed. Please try again.');
            }
          }}>
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      {/* Triage Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Triage Configuration</CardTitle>
          <CardDescription>Configure automated triage rules</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={triageConfig.autoTriage}
                  onChange={(e) => setTriageConfig({ ...triageConfig, autoTriage: e.target.checked })}
                  className="rounded"
                />
                <span className="text-sm">Enable Auto-Triage</span>
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity Threshold</label>
              <select
                value={triageConfig.severityThreshold}
                onChange={(e) => setTriageConfig({ ...triageConfig, severityThreshold: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
              >
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and above</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Confidence Threshold</label>
              <input
                type="number"
                value={triageConfig.confidenceThreshold}
                onChange={(e) => setTriageConfig({ ...triageConfig, confidenceThreshold: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                min="0"
                max="100"
              />
            </div>
            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={triageConfig.duplicateDetection}
                  onChange={(e) => setTriageConfig({ ...triageConfig, duplicateDetection: e.target.checked })}
                  className="rounded"
                />
                <span className="text-sm">Enable Duplicate Detection</span>
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Search className="h-4 w-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
              />
            </div>
            
            <div className="flex items-center space-x-2">
              <Filter className="h-4 w-4 text-gray-500" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            
            <div className="flex items-center space-x-2">
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
              >
                <option value="all">All Status</option>
                <option value="submitted">Submitted</option>
                <option value="triaged">Triaged</option>
                <option value="resolved">Resolved</option>
                <option value="not_applicable">Not Applicable</option>
                <option value="duplicate">Duplicate</option>
                <option value="spam">Spam</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredAndSortedFindings().map((finding) => (
          <Card key={finding.id}>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className="text-2xl">{getTypeIcon(finding.type)}</div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <Badge className={getSeverityColor(finding.severity)}>
                        {finding.severity.toUpperCase()}
                      </Badge>
                      <Badge className={getStatusColor(finding.status)}>
                        {finding.status.replace('_', ' ').toUpperCase()}
                      </Badge>
                      {finding.cve && (
                        <Badge variant="outline" className="text-xs">
                          {finding.cve}
                        </Badge>
                      )}
                      <Badge variant="outline" className="text-xs">
                        {finding.confidence}% confidence
                      </Badge>
                    </div>
                    <CardTitle className="text-lg">{finding.title}</CardTitle>
                    <CardDescription className="mt-1">
                      <div className="flex items-center space-x-4 text-sm">
                        <span className="flex items-center">
                          <Target className="h-3 w-3 mr-1" />
                          {finding.target}
                        </span>
                        <span className="flex items-center">
                          <Calendar className="h-3 w-3 mr-1" />
                          {new Date(finding.createdAt).toLocaleDateString()}
                        </span>
                        <span className="flex items-center">
                          <User className="h-3 w-3 mr-1" />
                          {finding.reporter}
                        </span>
                      </div>
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Button size="sm" variant="outline" onClick={() => setSelectedFinding(selectedFinding === finding.id ? null : finding.id)}>
                    <Eye className="h-3 w-3" />
                  </Button>
                  <Button size="sm" variant="outline">
                    <Edit className="h-3 w-3" />
                  </Button>
                  <Button size="sm" variant="outline">
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-4">
                <p className="text-gray-700">{finding.description}</p>
                
                <div className="flex flex-wrap gap-2">
                  {finding.tags.map(tag => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      <Tag className="h-3 w-3 mr-1" />
                      {tag}
                    </Badge>
                  ))}
                </div>

                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <div className="text-gray-500">CVSS Score</div>
                    <div className="font-bold text-lg">{finding.cvss || 'N/A'}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Risk Score</div>
                    <div className="font-bold text-lg">{finding.risk_score.toFixed(1)}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Impact</div>
                    <div className="font-bold">{finding.impact}</div>
                  </div>
                </div>

                {/* Detailed View */}
                {selectedFinding === finding.id && (
                  <div className="border-t pt-4">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h4 className="font-medium mb-2">Technical Details</h4>
                        <div className="space-y-2 text-sm">
                          <div>
                            <span className="font-medium">Likelihood:</span> {finding.likelihood}
                          </div>
                          <div>
                            <span className="font-medium">Remediation:</span> {finding.remediation}
                          </div>
                          {finding.triagedBy && (
                            <div>
                              <span className="font-medium">Triaged by:</span> {finding.triagedBy} on {new Date(finding.triagedAt!).toLocaleDateString()}
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="font-medium mb-2">Evidence</h4>
                        <div className="space-y-2">
                          {finding.evidence.map((evidence, index) => (
                            <div key={index} className="text-sm">
                              <div className="font-medium">{evidence.type}:</div>
                              <div className="text-gray-600">{evidence.description}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                    
                    <div className="mt-4 pt-4 border-t">
                      <h4 className="font-medium mb-2">Comments</h4>
                      <div className="space-y-2">
                        {finding.comments.map(comment => (
                          <div key={comment.id} className="bg-gray-50 rounded p-2 text-sm">
                            <div className="flex items-center space-x-2 mb-1">
                              <span className="font-medium">{comment.author}</span>
                              <span className="text-gray-500 text-xs">
                                {new Date(comment.createdAt).toLocaleString()}
                              </span>
                            </div>
                            <div>{comment.content}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex space-x-2 mt-4">
                      <button
                        onClick={() => handleTriage(finding.id, 'triaged')}
                        className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center justify-center space-x-2"
                      >
                        <span>Triage</span>
                      </button>
                    </div>

                    <div className="flex justify-end space-x-2 mt-4">
                      <Button size="sm" variant="outline">
                        <Download className="h-3 w-3 mr-1" />
                        Export Finding
                      </Button>
                      {finding.status === 'submitted' && (
                        <>
                          <Button size="sm" onClick={() => handleTriage(finding.id, 'resolved')}>
                            Resolve
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => handleTriage(finding.id, 'not_applicable')}>
                            Not Applicable
                          </Button>
                        </>
                      )}
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