/**
 * Shared UI helper functions for job management pages
 * Used across Exploitation, Reconnaissance, and Scanning pages
 */

export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'paused' | 'validated';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'informational';
export type SafetyLevel = 'safe' | 'medium' | 'aggressive';
export type LogLevel = 'info' | 'warning' | 'error';

/**
 * Get status badge colors for job status
 */
export const getStatusColor = (status: string): string => {
  switch (status) {
    case 'running':
      return 'text-blue-600 bg-blue-100';
    case 'completed':
    case 'validated':
      return 'text-green-600 bg-green-100';
    case 'failed':
      return 'text-red-600 bg-red-100';
    case 'pending':
      return 'text-yellow-600 bg-yellow-100';
    case 'paused':
      return 'text-gray-600 bg-gray-100';
    default:
      return 'text-gray-600 bg-gray-100';
  }
};

/**
 * Get severity badge colors
 */
export const getSeverityColor = (severity: string): string => {
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
    case 'informational':
      return 'bg-gray-100 text-gray-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

/**
 * Get safety level badge colors
 */
export const getSafetyColor = (level: string): string => {
  switch (level) {
    case 'safe':
      return 'bg-green-100 text-green-800';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800';
    case 'aggressive':
      return 'bg-red-100 text-red-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

/**
 * Get log level colors
 */
export const getLogLevelColor = (level: string): string => {
  switch (level) {
    case 'info':
      return 'text-blue-600';
    case 'warning':
      return 'text-yellow-600';
    case 'error':
      return 'text-red-600';
    default:
      return 'text-gray-600';
  }
};

/**
 * Get status icon component name
 */
export const getStatusIcon = (status: string): string => {
  switch (status) {
    case 'running':
      return 'Play';
    case 'completed':
    case 'validated':
      return 'CheckCircle';
    case 'failed':
      return 'XCircle';
    case 'pending':
      return 'Clock';
    case 'paused':
      return 'Pause';
    default:
      return 'Clock';
  }
};
