import React, { memo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import {
  Play,
  Pause,
  RotateCcw,
  Clock,
  CheckCircle,
  XCircle,
  Eye,
  Target,
  Globe,
  Shield
} from 'lucide-react';
import { getStatusColor, type JobStatus } from '../../utils/jobUIHelpers';

interface JobCardProps {
  id: string;
  programName: string;
  target: string;
  status: JobStatus | string;
  progress: number;
  startTime?: string;
  endTime?: string;
  tools?: string[];
  results?: Record<string, number>;
  icon?: 'globe' | 'target' | 'shield';
  onPause?: () => void;
  onResume?: () => void;
  onStop?: () => void;
  onRestart?: () => void;
  onView?: () => void;
  selectedJob?: string | null;
  children?: React.ReactNode;
  extraActions?: React.ReactNode;
}

export const JobCard: React.FC<JobCardProps> = ({
  id,
  programName,
  target,
  status,
  progress,
  tools,
  results,
  icon = 'globe',
  onPause,
  onResume,
  onStop,
  onRestart,
  onView,
  selectedJob,
  children,
  extraActions
}) => {
  const IconComponent = icon === 'globe' ? Globe : icon === 'target' ? Target : Shield;
  const StatusIcon = status === 'running' ? Play
    : status === 'completed' || status === 'validated' ? CheckCircle
    : status === 'failed' ? XCircle
    : status === 'pending' ? Clock
    : status === 'paused' ? Pause
    : Clock;

  return (
    <Card key={id}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-full ${getStatusColor(status)}`}>
              <StatusIcon className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-lg">{programName}</CardTitle>
              <CardDescription className="flex items-center mt-1">
                <IconComponent className="h-4 w-4 mr-1" />
                {target}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Badge className={getStatusColor(status)}>
              {status.toUpperCase()}
            </Badge>
            {status === 'running' && (
              <div className="flex space-x-1">
                {onPause && (
                  <Button size="sm" variant="outline" onClick={onPause}>
                    <Pause className="h-3 w-3" />
                  </Button>
                )}
                {onStop && (
                  <Button size="sm" variant="outline" onClick={onStop}>
                    <XCircle className="h-3 w-3" />
                  </Button>
                )}
              </div>
            )}
            {status === 'paused' && onResume && (
              <Button size="sm" variant="outline" onClick={onResume}>
                <Play className="h-3 w-3" />
              </Button>
            )}
            {(status === 'completed' || status === 'failed') && onRestart && (
              <Button size="sm" variant="outline" onClick={onRestart}>
                <RotateCcw className="h-3 w-3" />
              </Button>
            )}
            {extraActions}
            {onView && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => onView()}
              >
                <Eye className="h-3 w-3" />
              </Button>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <div className="space-y-4">
          {/* Progress */}
          <div>
            <div className="flex justify-between text-sm text-gray-600 mb-1">
              <span>Progress</span>
              <span>{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>

          {/* Results Grid */}
          {results && (
            <div className="grid grid-cols-4 gap-4">
              {Object.entries(results).map(([key, value]) => (
                <div key={key} className="text-center">
                  <div className="text-lg font-bold text-blue-600">{value}</div>
                  <div className="text-xs text-gray-500 capitalize">{key}</div>
                </div>
              ))}
            </div>
          )}

          {/* Tools */}
          {tools && tools.length > 0 && (
            <div>
              <div className="text-sm text-gray-600 mb-2">Tools Used</div>
              <div className="flex flex-wrap gap-1">
                {tools.map(tool => (
                  <Badge key={tool} variant="secondary" className="text-xs">
                    {tool}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Detailed View */}
          {selectedJob === id && children}
        </div>
      </CardContent>
    </Card>
  );
};

export const MemoizedJobCard = memo(JobCard);
