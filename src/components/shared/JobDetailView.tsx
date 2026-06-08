import React from 'react';
import { Button } from '../ui/button';
import { Download, Settings } from 'lucide-react';

interface JobDetailViewProps {
  title?: string;
  onExport?: () => void;
  onConfigure?: () => void;
  showButtons?: boolean;
  children?: React.ReactNode;
}

export const JobDetailView: React.FC<JobDetailViewProps> = ({
  title = 'Details',
  onExport,
  onConfigure,
  showButtons = true,
  children
}) => {
  return (
    <div className="border-t pt-4">
      <h4 className="font-medium mb-3">{title}</h4>
      {children}
      {showButtons && (
        <div className="flex justify-end space-x-2 mt-3">
          {onExport && (
            <Button size="sm" variant="outline" onClick={onExport}>
              <Download className="h-3 w-3 mr-1" />
              Export Results
            </Button>
          )}
          {onConfigure && (
            <Button size="sm" variant="outline" onClick={onConfigure}>
              <Settings className="h-3 w-3 mr-1" />
              Configure
            </Button>
          )}
        </div>
      )}
    </div>
  );
};
