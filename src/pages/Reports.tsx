import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import {
  Send,
  Eye,
  Plus,
  Filter,
  Edit,
  Trash2,
  Globe,
  DollarSign,
  Calendar,
  User,
  Tag
} from 'lucide-react';
import { JobDetailView } from '../components/shared/JobDetailView';

interface Report {
  id: string;
  programId: string;
  programName: string;
  title: string;
  template: string;
  status: 'draft' | 'ready' | 'submitted' | 'accepted' | 'rejected' | 'duplicate';
  platform: 'hackerone' | 'bugcrowd' | 'yeswehack' | 'intigriti' | 'custom';
  severity: 'critical' | 'high' | 'medium' | 'low';
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    description: string;
    evidence: string[];
  }>;
  bountyAmount?: number;
  currency: 'USD' | 'EUR' | 'GBP';
  submittedAt?: string;
  createdAt: string;
  updatedAt: string;
  submittedBy?: string;
  reportUrl?: string;
  submissionResponse?: string;
}

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  platform: 'hackerone' | 'bugcrowd' | 'yeswehack' | 'intigriti' | 'custom';
  sections: string[];
  defaultSeverity: 'critical' | 'high' | 'medium' | 'low';
}

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [selectedReport, setSelectedReport] = useState<string | null>(null);
  const [isNewReportOpen, setIsNewReportOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterPlatform, setFilterPlatform] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  const reportTemplates: ReportTemplate[] = [
    {
      id: '1',
      name: 'HackerOne Standard',
      description: 'Standard template for HackerOne submissions',
      platform: 'hackerone',
      sections: ['summary', 'technical_details', 'impact', 'reproduction_steps', 'remediation', 'evidence'],
      defaultSeverity: 'medium'
    },
    {
      id: '2',
      name: 'Bugcrowd VRT',
      description: 'Bugcrowd Vulnerability Rating Taxonomy template',
      platform: 'bugcrowd',
      sections: ['vulnerability_type', 'severity', 'description', 'steps_to_reproduce', 'impact', 'fix_guidance'],
      defaultSeverity: 'high'
    },
    {
      id: '3',
      name: 'YesWeHack Technical',
      description: 'Technical report template for YesWeHack',
      platform: 'yeswehack',
      sections: ['technical_summary', 'vulnerability_details', 'proof_of_concept', 'business_impact', 'recommendations'],
      defaultSeverity: 'high'
    },
    {
      id: '4',
      name: 'Intigriti Detailed',
      description: 'Detailed report template for Intigriti',
      platform: 'intigriti',
      sections: ['executive_summary', 'technical_analysis', 'exploitation_scenario', 'risk_assessment', 'mitigation'],
      defaultSeverity: 'medium'
    },
    {
      id: '5',
      name: 'Custom Template',
      description: 'Custom report template',
      platform: 'custom',
      sections: ['summary', 'details', 'impact', 'recommendations'],
      defaultSeverity: 'medium'
    }
  ];

  useEffect(() => {
    // Simulate fetching reports
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const res = await axios.get('/api/reports');
      const data = (res as any).data.data || [];
      setReports(data.map((r: any) => ({
        id: r.id,
        title: r.title,
        type: r.type,
        status: r.status,
        summary: r.summary,
        target: r.target,
        severity: r.riskLevel,
        findingsCount: r.findingsCount,
        criticalCount: r.criticalCount,
        highCount: r.highCount,
        mediumCount: r.mediumCount,
        lowCount: r.lowCount,
        createdBy: r.createdBy,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
        submittedAt: r.submittedAt,
        currency: 'USD'
      })));
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    }
  };

  const handleCreateReport = async () => {
    if (!selectedTemplate) {
      alert('Please select a report template');
      return;
    }

    const template = reportTemplates.find(t => t.id === selectedTemplate);
    if (!template) return;

    const newReport: Report = {
      id: Date.now().toString(),
      programId: '1',
      programName: 'Manual Report',
      title: 'New Security Report',
      template: template.name,
      status: 'draft',
      platform: template.platform,
      severity: template.defaultSeverity,
      findings: [],
      currency: 'USD',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    setReports([newReport, ...reports]);
    setIsNewReportOpen(false);
  };

  const handleSubmitReport = async (reportId: string) => {
    setReports(prev => prev.map(report => 
      report.id === reportId 
        ? { 
            ...report, 
            status: 'submitted',
            submittedAt: new Date().toISOString(),
            submittedBy: 'security_analyst',
            submissionResponse: 'Report submitted successfully and is under review'
          }
        : report
    ));
  };

  const handleDeleteReport = async (reportId: string) => {
    setReports(prev => prev.filter(report => report.id !== reportId));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'draft':
        return 'bg-gray-100 text-gray-800';
      case 'ready':
        return 'bg-blue-100 text-blue-800';
      case 'submitted':
        return 'bg-yellow-100 text-yellow-800';
      case 'accepted':
        return 'bg-green-100 text-green-800';
      case 'rejected':
        return 'bg-red-100 text-red-800';
      case 'duplicate':
        return 'bg-purple-100 text-purple-800';
      default:
        return 'bg-gray-100 text-gray-800';
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
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'hackerone':
        return '🔴';
      case 'bugcrowd':
        return '🟢';
      case 'yeswehack':
        return '🔵';
      case 'intigriti':
        return '🟣';
      default:
        return '📄';
    }
  };

  const filteredReports = reports.filter(report => {
    const matchesStatus = filterStatus === 'all' || report.status === filterStatus;
    const matchesPlatform = filterPlatform === 'all' || report.platform === filterPlatform;
    const matchesSeverity = filterSeverity === 'all' || report.severity === filterSeverity;
    return matchesStatus && matchesPlatform && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Report Generation</h1>
          <p className="text-gray-600 mt-1">Generate and submit vulnerability reports</p>
        </div>
        <Button onClick={() => setIsNewReportOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          New Report
        </Button>
      </div>

      {/* New Report Modal */}
      {isNewReportOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create New Report</h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Report Template</label>
                <select
                  value={selectedTemplate}
                  onChange={(e) => setSelectedTemplate(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select a template</option>
                  {reportTemplates.map(template => (
                    <option key={template.id} value={template.id}>
                      {template.name} - {template.description}
                    </option>
                  ))}
                </select>
              </div>

              {selectedTemplate && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Template Sections</label>
                  <div className="space-y-1">
                    {reportTemplates.find(t => t.id === selectedTemplate)?.sections.map(section => (
                      <div key={section} className="flex items-center">
                        <input type="checkbox" checked className="mr-2" readOnly />
                        <span className="text-sm capitalize">{section.replace('_', ' ')}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" onClick={() => setIsNewReportOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateReport}>
                Create Report
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Filter className="h-4 w-4 text-gray-500" />
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
              >
                <option value="all">All Status</option>
                <option value="draft">Draft</option>
                <option value="ready">Ready</option>
                <option value="submitted">Submitted</option>
                <option value="accepted">Accepted</option>
                <option value="rejected">Rejected</option>
                <option value="duplicate">Duplicate</option>
              </select>
            </div>
            
            <div className="flex items-center space-x-2">
              <Globe className="h-4 w-4 text-gray-500" />
              <select
                value={filterPlatform}
                onChange={(e) => setFilterPlatform(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
              >
                <option value="all">All Platforms</option>
                <option value="hackerone">HackerOne</option>
                <option value="bugcrowd">Bugcrowd</option>
                <option value="yeswehack">YesWeHack</option>
                <option value="intigriti">Intigriti</option>
                <option value="custom">Custom</option>
              </select>
            </div>
            
            <div className="flex items-center space-x-2">
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
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reports List */}
      <div className="space-y-4">
        {filteredReports.map((report) => (
          <Card key={report.id}>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className="text-2xl">{getPlatformIcon(report.platform)}</div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <Badge className={getSeverityColor(report.severity)}>
                        {report.severity.toUpperCase()}
                      </Badge>
                      <Badge className={getStatusColor(report.status)}>
                        {report.status.toUpperCase()}
                      </Badge>
                      {report.bountyAmount && (
                        <Badge variant="outline" className="text-green-600">
                          <DollarSign className="h-3 w-3 mr-1" />
                          {report.bountyAmount} {report.currency}
                        </Badge>
                      )}
                    </div>
                    <CardTitle className="text-lg">{report.title}</CardTitle>
                    <CardDescription className="mt-1">
                      <div className="flex items-center space-x-4 text-sm">
                        <span className="flex items-center">
                          <Globe className="h-3 w-3 mr-1" />
                          {report.platform}
                        </span>
                        <span className="flex items-center">
                          <Calendar className="h-3 w-3 mr-1" />
                          {new Date(report.createdAt).toLocaleDateString()}
                        </span>
                        <span className="flex items-center">
                          <User className="h-3 w-3 mr-1" />
                          {report.programName}
                        </span>
                        <span className="flex items-center">
                          <Tag className="h-3 w-3 mr-1" />
                          {report.findings.length} findings
                        </span>
                      </div>
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Button size="sm" variant="outline" onClick={() => setSelectedReport(selectedReport === report.id ? null : report.id)}>
                    <Eye className="h-3 w-3" />
                  </Button>
                  {report.status === 'draft' && (
                    <>
                      <Button size="sm" variant="outline">
                        <Edit className="h-3 w-3" />
                      </Button>
                      <Button size="sm" onClick={() => handleSubmitReport(report.id)}>
                        <Send className="h-3 w-3" />
                      </Button>
                    </>
                  )}
                  <Button size="sm" variant="outline" onClick={() => handleDeleteReport(report.id)}>
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-gray-600 mb-2">Template: {report.template}</div>
                  <div className="flex flex-wrap gap-1">
                    {report.findings.map(finding => (
                      <Badge key={finding.id} variant="outline" className="text-xs">
                        {finding.title}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Detailed View */}
                {selectedReport === report.id && (
                  <div className="border-t pt-4">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h4 className="font-medium mb-2">Report Details</h4>
                        <div className="space-y-2 text-sm">
                          <div>
                            <span className="font-medium">Status:</span> {report.status}
                          </div>
                          <div>
                            <span className="font-medium">Platform:</span> {report.platform}
                          </div>
                          <div>
                            <span className="font-medium">Template:</span> {report.template}
                          </div>
                          {report.submittedAt && (
                            <div>
                              <span className="font-medium">Submitted:</span> {new Date(report.submittedAt).toLocaleString()}
                            </div>
                          )}
                          {report.submittedBy && (
                            <div>
                              <span className="font-medium">Submitted by:</span> {report.submittedBy}
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="font-medium mb-2">Findings</h4>
                        <div className="space-y-2">
                          {report.findings.map(finding => (
                            <div key={finding.id} className="border rounded p-2 text-sm">
                              <div className="font-medium">{finding.title}</div>
                              <div className="text-gray-600">{finding.description}</div>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {finding.evidence.map((evidence, index) => (
                                  <Badge key={index} variant="outline" className="text-xs">
                                    {evidence}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                    
                    {report.submissionResponse && (
                      <div className="mt-4 pt-4 border-t">
                        <h4 className="font-medium mb-2">Submission Response</h4>
                        <div className="bg-gray-50 rounded p-3 text-sm">
                          {report.submissionResponse}
                        </div>
                      </div>
                    )}

                    <JobDetailView showButtons={true} />
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