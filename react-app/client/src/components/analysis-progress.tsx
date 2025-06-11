import { useEffect, useState } from "react";
import { Activity, CheckCircle, Clock, FileText, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useQuery } from "@tanstack/react-query";

interface AnalysisProgressProps {
  jobId: number;
  onComplete: () => void;
}

interface ProgressStep {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  completed: boolean;
  active: boolean;
}

export default function AnalysisProgress({ jobId, onComplete }: AnalysisProgressProps) {
  const [startTime] = useState(Date.now());
  const [elapsedTime, setElapsedTime] = useState(0);

  // Poll for progress updates
  const { data: progress, isLoading } = useQuery({
    queryKey: [`/api/analysis/${jobId}/progress`],
    refetchInterval: 1000, // Poll every second
    enabled: !!jobId
  });

  // Update elapsed time
  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    return () => clearInterval(timer);
  }, [startTime]);

  // Check if analysis is complete
  useEffect(() => {
    if (progress?.status === 'completed') {
      onComplete();
    }
  }, [progress, onComplete]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const getProgressSteps = (): ProgressStep[] => {
    const currentPercentage = progress?.percentage || 0;
    
    return [
      {
        id: 'upload',
        title: 'File Upload & Validation',
        description: 'Validating and processing uploaded files',
        icon: <FileText className="w-4 h-4" />,
        completed: currentPercentage > 0,
        active: currentPercentage === 0
      },
      {
        id: 'parsing',
        title: 'Language Detection & Parsing',
        description: 'Analyzing code structure and building ASTs',
        icon: <Activity className="w-4 h-4" />,
        completed: currentPercentage > 25,
        active: currentPercentage > 0 && currentPercentage <= 25
      },
      {
        id: 'graphs',
        title: 'CFG/DFG Graph Generation',
        description: 'Creating control and data flow graphs',
        icon: <Zap className="w-4 h-4" />,
        completed: currentPercentage > 50,
        active: currentPercentage > 25 && currentPercentage <= 50
      },
      {
        id: 'analysis',
        title: 'Rule Engine Analysis',
        description: 'Applying OWASP security rules and patterns',
        icon: <Clock className="w-4 h-4" />,
        completed: currentPercentage > 75,
        active: currentPercentage > 50 && currentPercentage <= 75
      },
      {
        id: 'report',
        title: 'Report Generation',
        description: 'Compiling security analysis results',
        icon: <CheckCircle className="w-4 h-4" />,
        completed: currentPercentage >= 100,
        active: currentPercentage > 75 && currentPercentage < 100
      }
    ];
  };

  const steps = getProgressSteps();
  const currentPercentage = progress?.percentage || 0;

  const getCurrentMessage = () => {
    if (currentPercentage <= 25) return 'Processing and validating uploaded files...';
    if (currentPercentage <= 50) return 'Parsing code and detecting languages...';
    if (currentPercentage <= 75) return 'Generating control and data flow graphs...';
    if (currentPercentage < 100) return 'Analyzing code with security rules...';
    return 'Finalizing security report...';
  };

  if (isLoading && !progress) {
    return (
      <Card className="bg-white rounded-xl border border-gray-200">
        <CardContent className="p-6">
          <div className="flex items-center justify-center space-x-2">
            <div className="w-4 h-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="text-sm text-gray-600">Initializing analysis...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-white rounded-xl border border-gray-200">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center">
            <Activity className="w-5 h-5 mr-2 text-primary animate-pulse" />
            Analysis Progress
          </CardTitle>
          <span className="text-sm text-gray-500">
            {formatTime(elapsedTime)}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Progress Steps */}
        <div className="space-y-4">
          {steps.map((step, index) => (
            <div key={step.id} className="flex items-start space-x-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
                step.completed
                  ? 'bg-green-100 text-green-600'
                  : step.active
                  ? 'bg-blue-100 text-blue-600 animate-pulse'
                  : 'bg-gray-100 text-gray-400'
              }`}>
                {step.completed ? (
                  <CheckCircle className="w-4 h-4" />
                ) : step.active ? (
                  <div className="w-3 h-3 animate-spin rounded-full border-2 border-blue-600 border-t-transparent" />
                ) : (
                  <span className="text-xs font-medium">{index + 1}</span>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <h4 className={`text-sm font-medium ${
                  step.completed ? 'text-green-900' : step.active ? 'text-blue-900' : 'text-gray-500'
                }`}>
                  {step.title}
                </h4>
                <p className={`text-xs mt-1 ${
                  step.completed ? 'text-green-700' : step.active ? 'text-blue-700' : 'text-gray-500'
                }`}>
                  {step.description}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">
              Overall Progress
            </span>
            <span className="text-sm font-medium text-gray-700">
              {currentPercentage}%
            </span>
          </div>
          <Progress value={currentPercentage} className="h-2" />
          <p className="text-xs text-gray-600">
            {getCurrentMessage()}
          </p>
        </div>

        {/* Analysis Stats */}
        {progress && (
          <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-200">
            <div className="text-center">
              <div className="text-lg font-semibold text-gray-900">
                {progress.processedFiles || 0}
              </div>
              <div className="text-xs text-gray-600">
                Files Processed
              </div>
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-gray-900">
                {progress.totalFiles || 0}
              </div>
              <div className="text-xs text-gray-600">
                Total Files
              </div>
            </div>
          </div>
        )}

        {/* Status Indicator */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
          <div className="flex items-center">
            <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse mr-2" />
            <span className="text-sm text-blue-800 font-medium">
              Analysis in progress...
            </span>
          </div>
          <p className="text-xs text-blue-700 mt-1">
            This may take a few minutes depending on code complexity and file size.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
