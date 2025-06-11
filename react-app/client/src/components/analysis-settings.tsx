import { useState, useMemo } from "react";
import { Settings, Zap, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { getCategorySummary } from "@/lib/rules/owasp-rules";
import type { FileUpload as FileUploadType } from "@shared/schema";

interface AnalysisSettingsProps {
  uploadedFiles: FileUploadType[];
  onStartAnalysis: (jobId: number) => void;
  onAnalysisStart: () => void;
  disabled?: boolean;
}

const COMPREHENSIVE_SECURITY_RULES = getCategorySummary();

export default function AnalysisSettings({ 
  uploadedFiles, 
  onStartAnalysis, 
  onAnalysisStart, 
  disabled 
}: AnalysisSettingsProps) {
  const { toast } = useToast();

  // Detect unique languages from uploaded files
  const detectedLanguages = useMemo(() => {
    const languages = new Set(uploadedFiles.map(f => f.language));
    return Array.from(languages);
  }, [uploadedFiles]);

  const createJobMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('POST', '/api/analysis');
      return response.json();
    }
  });

  const uploadFilesMutation = useMutation({
    mutationFn: async ({ jobId, files }: { jobId: number; files: File[] }) => {
      const formData = new FormData();
      files.forEach(file => formData.append('files', file));
      
      const response = await fetch(`/api/analysis/${jobId}/files`, {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }
      
      return response.json();
    }
  });

  const startAnalysisMutation = useMutation({
    mutationFn: async (jobId: number) => {
      const response = await apiRequest('POST', `/api/analysis/${jobId}/start`);
      return response.json();
    }
  });

  

  const handleStartAnalysis = async () => {
    if (uploadedFiles.length === 0) {
      toast({
        title: "No Files",
        description: "Please upload at least one file before starting analysis.",
        variant: "destructive"
      });
      return;
    }

    try {
      onAnalysisStart();
      
      // Step 1: Create analysis job
      const job = await createJobMutation.mutateAsync();
      
      // Step 2: Upload files
      const files = uploadedFiles.map(f => f.file);
      await uploadFilesMutation.mutateAsync({ jobId: job.id, files });
      
      // Step 3: Start analysis
      await startAnalysisMutation.mutateAsync(job.id);
      
      onStartAnalysis(job.id);
      
      const totalRules = COMPREHENSIVE_SECURITY_RULES.reduce((sum, cat) => sum + cat.count, 0);
      toast({
        title: "Comprehensive Security Analysis Started",
        description: `Analyzing ${uploadedFiles.length} file(s) with ${totalRules} security rules across ${COMPREHENSIVE_SECURITY_RULES.length} categories.`
      });
      
    } catch (error) {
      console.error('Analysis failed:', error);
      toast({
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Failed to start analysis",
        variant: "destructive"
      });
    }
  };

  const getLanguageColor = (language: string) => {
    const colors: Record<string, string> = {
      'Python': 'bg-blue-100 text-blue-800',
      'JavaScript': 'bg-yellow-100 text-yellow-800',
      'TypeScript': 'bg-blue-100 text-blue-800',
      'Java': 'bg-red-100 text-red-800',
      'C++': 'bg-purple-100 text-purple-800',
      'C#': 'bg-indigo-100 text-indigo-800',
      'PHP': 'bg-violet-100 text-violet-800',
      'Ruby': 'bg-red-100 text-red-800'
    };
    return colors[language] || 'bg-gray-100 text-gray-800';
  };

  const isLoading = createJobMutation.isPending || uploadFilesMutation.isPending || startAnalysisMutation.isPending;

  return (
    <Card className="bg-white rounded-xl border border-gray-200">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Settings className="w-5 h-5 mr-2 text-primary" />
          Analysis Settings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Detected Languages */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Detected Languages
          </label>
          {detectedLanguages.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {detectedLanguages.map((language) => (
                <Badge key={language} className={getLanguageColor(language)}>
                  {language}
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No files uploaded yet</p>
          )}
        </div>

        {/* Comprehensive Security Ruleset */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Comprehensive Security Analysis
          </label>
          
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-4 mb-4">
            <div className="flex items-center mb-2">
              <CheckCircle className="w-5 h-5 text-green-600 mr-2" />
              <h4 className="text-sm font-semibold text-gray-900">Full Security Scan Enabled</h4>
            </div>
            <p className="text-xs text-gray-700">
              All {COMPREHENSIVE_SECURITY_RULES.reduce((sum, cat) => sum + cat.count, 0)} security rules across {COMPREHENSIVE_SECURITY_RULES.length} frameworks (OWASP, NIST, CIS, SANS, ISO 27001, PCI DSS, GDPR, HIPAA, SOX, FISMA, and more) are automatically enabled for comprehensive security coverage.
            </p>
          </div>
          
          <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto border rounded-lg p-3">
            {COMPREHENSIVE_SECURITY_RULES.map((category) => (
              <div key={category.category} className="flex items-center justify-between py-2 px-3 bg-gray-50 rounded">
                <div className="flex-1">
                  <span className="text-sm font-medium text-gray-900">
                    {category.category}: {category.name}
                  </span>
                </div>
                <Badge variant="secondary" className="text-xs">
                  {category.count} rules
                </Badge>
              </div>
            ))}
          </div>
        </div>

        {/* Analysis Summary */}
        {uploadedFiles.length > 0 && (
          <div className="bg-gray-50 rounded-lg p-4 space-y-2">
            <h4 className="text-sm font-medium text-gray-900">Analysis Summary</h4>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-600">Files:</span>
                <span className="font-medium ml-2">{uploadedFiles.length}</span>
              </div>
              <div>
                <span className="text-gray-600">Security Rules:</span>
                <span className="font-medium ml-2">{COMPREHENSIVE_SECURITY_RULES.reduce((sum, cat) => sum + cat.count, 0)}</span>
              </div>
              <div>
                <span className="text-gray-600">Languages:</span>
                <span className="font-medium ml-2">{detectedLanguages.length}</span>
              </div>
              <div>
                <span className="text-gray-600">Categories:</span>
                <span className="font-medium ml-2">{COMPREHENSIVE_SECURITY_RULES.length}</span>
              </div>
            </div>
          </div>
        )}

        {/* Start Analysis Button */}
        <Button
          className="w-full bg-primary text-white hover:bg-blue-700 font-medium"
          onClick={handleStartAnalysis}
          disabled={disabled || uploadedFiles.length === 0 || isLoading}
        >
          {isLoading ? (
            <>
              <div className="w-4 h-4 mr-2 animate-spin rounded-full border-2 border-white border-t-transparent" />
              Starting Analysis...
            </>
          ) : (
            <>
              <Zap className="w-5 h-5 mr-2" />
              Start Security Analysis
            </>
          )}
        </Button>

        {/* Privacy Notice */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
          <div className="flex items-start">
            <CheckCircle className="w-4 h-4 text-blue-600 mt-0.5 mr-2 flex-shrink-0" />
            <div>
              <h4 className="text-sm font-semibold text-blue-900 mb-1">Privacy Guarantee</h4>
              <p className="text-xs text-blue-800">
                Your code files and analysis results are automatically deleted from our servers after processing to ensure complete privacy.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
