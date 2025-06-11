import { useState } from "react";
import { Shield, Github, FileText, Settings, Activity } from "lucide-react";
import FileUpload from "@/components/file-upload";
import AnalysisSettings from "@/components/analysis-settings";
import AnalysisProgress from "@/components/analysis-progress";
import SecurityDashboard from "@/components/security-dashboard";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { FileUpload as FileUploadType, AnalysisProgress as AnalysisProgressType } from "@shared/schema";

export default function Home() {
  const [uploadedFiles, setUploadedFiles] = useState<FileUploadType[]>([]);
  const [analysisJobId, setAnalysisJobId] = useState<number | null>(null);
  const [analysisProgress, setAnalysisProgress] = useState<AnalysisProgressType | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  return (
    <div className="bg-surface min-h-screen">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Shield className="w-8 h-8 text-primary" />
                <h1 className="text-2xl font-bold text-gray-900">SecureCode SAST</h1>
              </div>
              <Badge variant="secondary" className="bg-primary/10 text-primary">
                Open Source
              </Badge>
            </div>
            <nav className="flex items-center space-x-6">
              <a href="#" className="text-gray-600 hover:text-gray-900 font-medium">Documentation</a>
              <a href="#" className="text-gray-600 hover:text-gray-900 font-medium">API</a>
              <Button variant="default" className="bg-primary hover:bg-blue-700">
                <Github className="w-4 h-4 mr-2" />
                GitHub
              </Button>
            </nav>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Panel - Upload and Configuration */}
          <div className="lg:col-span-1 space-y-6">
            <FileUpload 
              uploadedFiles={uploadedFiles}
              setUploadedFiles={setUploadedFiles}
              disabled={isAnalyzing}
            />
            
            <AnalysisSettings
              uploadedFiles={uploadedFiles}
              onStartAnalysis={setAnalysisJobId}
              onAnalysisStart={() => setIsAnalyzing(true)}
              disabled={isAnalyzing || uploadedFiles.length === 0}
            />
          </div>

          {/* Right Panel - Results and Reports */}
          <div className="lg:col-span-2 space-y-6">
            {isAnalyzing && analysisJobId && (
              <AnalysisProgress 
                jobId={analysisJobId}
                onComplete={() => setIsAnalyzing(false)}
              />
            )}
            
            {analysisJobId && !isAnalyzing && (
              <SecurityDashboard jobId={analysisJobId} />
            )}

            {/* Initial state when no analysis has been run */}
            {!analysisJobId && (
              <Card className="bg-white rounded-xl border border-gray-200 p-12 text-center">
                <Activity className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Ready to Analyze Your Code
                </h3>
                <p className="text-gray-600 mb-4">
                  Upload your source code files and configure your analysis settings to get started.
                </p>
                <ul className="text-sm text-gray-500 space-y-1">
                  <li>• Support for Python, JavaScript, Java, and more</li>
                  <li>• OWASP Top 10 vulnerability detection</li>
                  <li>• Detailed security reports with remediation advice</li>
                  <li>• Privacy-focused with automatic cleanup</li>
                </ul>
              </Card>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900 text-white mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="col-span-1 md:col-span-2">
              <div className="flex items-center space-x-2 mb-4">
                <Shield className="w-8 h-8 text-primary" />
                <h3 className="text-xl font-bold">SecureCode SAST</h3>
              </div>
              <p className="text-gray-300 mb-4">
                Open-source Static Application Security Testing tool designed to help developers identify and fix security vulnerabilities before they reach production.
              </p>
              <p className="text-sm text-gray-400">
                Built with ❤️ for the developer community. Inspired by Semgrep, CodeQL, and Joern.
              </p>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Documentation</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">API Reference</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Rule Library</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Language Support</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Community</h4>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">GitHub Repository</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Issue Tracker</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Discussions</a></li>
                <li><a href="#" className="text-gray-300 hover:text-white transition-colors">Contributing Guide</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-800 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              © 2024 SecureCode SAST. Licensed under MIT License.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a href="#" className="text-gray-400 hover:text-white transition-colors">
                <span className="sr-only">GitHub</span>
                <Github className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
