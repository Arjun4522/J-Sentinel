import { useCallback, useState } from "react";
import { Upload, X, FileCode, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import type { FileUpload as FileUploadType } from "@shared/schema";

interface FileUploadProps {
  uploadedFiles: FileUploadType[];
  setUploadedFiles: (files: FileUploadType[]) => void;
  disabled?: boolean;
}

const SUPPORTED_EXTENSIONS = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.cs', '.php', '.rb'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

function detectLanguage(filename: string): string {
  const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  const languageMap: Record<string, string> = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.jsx': 'JavaScript',
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    '.java': 'Java',
    '.cpp': 'C++',
    '.cs': 'C#',
    '.php': 'PHP',
    '.rb': 'Ruby'
  };
  return languageMap[extension] || 'Unknown';
}

export default function FileUpload({ uploadedFiles, setUploadedFiles, disabled }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const { toast } = useToast();

  const validateFile = (file: File): string | null => {
    const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
    
    if (!SUPPORTED_EXTENSIONS.includes(extension)) {
      return `Unsupported file type: ${extension}`;
    }
    
    if (file.size > MAX_FILE_SIZE) {
      return `File too large: ${(file.size / 1024 / 1024).toFixed(1)}MB (max 10MB)`;
    }
    
    return null;
  };

  const handleFiles = useCallback((files: FileList) => {
    const newFiles: FileUploadType[] = [];
    const errors: string[] = [];

    Array.from(files).forEach((file) => {
      const error = validateFile(file);
      if (error) {
        errors.push(`${file.name}: ${error}`);
        return;
      }

      // Check for duplicates
      if (uploadedFiles.some(f => f.file.name === file.name)) {
        errors.push(`${file.name}: File already uploaded`);
        return;
      }

      newFiles.push({
        id: Math.random().toString(36).substr(2, 9),
        file,
        language: detectLanguage(file.name),
        progress: 0
      });
    });

    if (errors.length > 0) {
      toast({
        title: "Upload Errors",
        description: errors.join('\n'),
        variant: "destructive"
      });
    }

    if (newFiles.length > 0) {
      setUploadedFiles([...uploadedFiles, ...newFiles]);
      toast({
        title: "Files Added",
        description: `Successfully added ${newFiles.length} file(s)`
      });
    }
  }, [uploadedFiles, setUploadedFiles, toast]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    if (!disabled) {
      setIsDragOver(true);
    }
  }, [disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    if (!disabled && e.dataTransfer.files) {
      handleFiles(e.dataTransfer.files);
    }
  }, [disabled, handleFiles]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      handleFiles(e.target.files);
    }
    e.target.value = ''; // Reset input
  }, [handleFiles]);

  const removeFile = useCallback((fileId: string) => {
    setUploadedFiles(uploadedFiles.filter(f => f.id !== fileId));
  }, [uploadedFiles, setUploadedFiles]);

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

  return (
    <Card className="bg-white rounded-xl border border-gray-200">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Upload className="w-5 h-5 mr-2 text-primary" />
          Upload Code Files
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Drop Zone */}
        <div
          className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer ${
            isDragOver
              ? 'border-primary bg-primary/5'
              : disabled
              ? 'border-gray-200 bg-gray-50 cursor-not-allowed'
              : 'border-gray-300 hover:border-primary'
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !disabled && document.getElementById('file-input')?.click()}
        >
          <input
            id="file-input"
            type="file"
            className="hidden"
            multiple
            accept={SUPPORTED_EXTENSIONS.join(',')}
            onChange={handleFileInput}
            disabled={disabled}
          />
          
          <FileCode className={`mx-auto h-12 w-12 mb-4 ${disabled ? 'text-gray-300' : 'text-gray-400'}`} />
          <p className={`text-sm mb-2 ${disabled ? 'text-gray-400' : 'text-gray-600'}`}>
            {disabled ? 'Upload disabled during analysis' : 'Drop your code files here or click to browse'}
          </p>
          <p className="text-xs text-gray-500">
            Supports: {SUPPORTED_EXTENSIONS.join(', ')}
          </p>
        </div>

        {/* Uploaded Files List */}
        {uploadedFiles.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-gray-700">Uploaded Files ({uploadedFiles.length})</h4>
            {uploadedFiles.map((fileUpload) => (
              <div key={fileUpload.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <FileCode className="w-4 h-4 text-gray-600" />
                  <div>
                    <span className="text-sm font-medium text-gray-900">{fileUpload.file.name}</span>
                    <div className="flex items-center space-x-2 mt-1">
                      <Badge className={`text-xs ${getLanguageColor(fileUpload.language)}`}>
                        {fileUpload.language}
                      </Badge>
                      <span className="text-xs text-gray-500">
                        ({(fileUpload.file.size / 1024).toFixed(1)} KB)
                      </span>
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeFile(fileUpload.id)}
                  disabled={disabled}
                  className="text-red-600 hover:text-red-800"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ))}
          </div>
        )}

        {/* Upload Guidelines */}
        {uploadedFiles.length === 0 && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start">
              <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5 mr-3" />
              <div>
                <h4 className="text-sm font-semibold text-blue-900 mb-1">Upload Guidelines</h4>
                <ul className="text-sm text-blue-800 space-y-1">
                  <li>• Maximum file size: 10MB per file</li>
                  <li>• Supported languages: Python, JavaScript, Java, C++, C#, PHP, Ruby</li>
                  <li>• Files are automatically deleted after analysis for privacy</li>
                  <li>• Upload source code files only (not compiled binaries)</li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
