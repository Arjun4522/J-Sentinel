import { useState } from "react";
import { BarChart3, Download, Eye, AlertTriangle, Shield, Clock, Network } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import VulnerabilityCard from "./vulnerability-card";
import GraphViewer from "./graph-viewer";
import type { SecurityReport } from "@shared/schema";

interface SecurityDashboardProps {
  jobId: number;
}

export default function SecurityDashboard({ jobId }: SecurityDashboardProps) {
  const [showAllVulnerabilities, setShowAllVulnerabilities] = useState(false);
  const { toast } = useToast();

  const { data: report, isLoading } = useQuery<SecurityReport>({
    queryKey: [`/api/analysis/${jobId}/results`],
    enabled: !!jobId
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="space-y-3">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded w-5/6"></div>
            <div className="h-4 bg-gray-200 rounded w-4/6"></div>
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return <div>No report data available</div>;
  }

  const maxVulnerabilitiesToShow = 5;
  const vulnerabilitiesToShow = showAllVulnerabilities 
    ? report.vulnerabilities || []
    : (report.vulnerabilities || []).slice(0, maxVulnerabilitiesToShow);
  const remainingCount = Math.max(0, (report.vulnerabilities || []).length - maxVulnerabilitiesToShow);

  const downloadReport = () => {
    try {
      const reportData = {
        ...report,
        exportedAt: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(reportData, null, 2)], {
        type: 'application/json'
      });
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${jobId}-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "Report Downloaded",
        description: "Security analysis report exported successfully."
      });
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "Failed to download the security report.",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gradient-to-r from-red-50 to-red-100 border border-red-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-red-600">Critical</p>
                <p className="text-3xl font-bold text-red-900">{report.criticalCount}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-orange-50 to-orange-100 border border-orange-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-orange-600">High</p>
                <p className="text-3xl font-bold text-orange-900">{report.highCount}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-yellow-50 to-yellow-100 border border-yellow-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-yellow-600">Medium</p>
                <p className="text-3xl font-bold text-yellow-900">{report.mediumCount}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-blue-50 to-blue-100 border border-blue-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-blue-600">Low</p>
                <p className="text-3xl font-bold text-blue-900">{report.lowCount}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Summary */}
      <Card className="bg-white rounded-xl border border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center">
              <BarChart3 className="w-5 h-5 mr-2 text-primary" />
              Analysis Summary
            </div>
            <Button onClick={downloadReport} variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export Report
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{report.filesAnalyzed}</div>
              <div className="text-sm text-gray-600">Files Analyzed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{report.linesOfCode.toLocaleString()}</div>
              <div className="text-sm text-gray-600">Lines of Code</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{report.rulesApplied}</div>
              <div className="text-sm text-gray-600">OWASP Rules</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary flex items-center justify-center">
                <Clock className="w-6 h-6 mr-1" />
                {report.analysisTime}
              </div>
              <div className="text-sm text-gray-600">Analysis Time</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Analysis Results Tabs */}
      <Card className="bg-white rounded-xl border border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="w-5 h-5 mr-2 text-primary" />
            Security Analysis Results
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="vulnerabilities" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="vulnerabilities" className="flex items-center">
                <Shield className="w-4 h-4 mr-2" />
                Vulnerabilities ({report.totalVulnerabilities})
              </TabsTrigger>
              <TabsTrigger value="graphs" className="flex items-center">
                <Network className="w-4 h-4 mr-2" />
                Code Graphs
              </TabsTrigger>
            </TabsList>

            <TabsContent value="vulnerabilities" className="mt-6">
              {report.vulnerabilities.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="w-12 h-12 text-green-500 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-green-900 mb-2">No Vulnerabilities Found</h3>
                  <p className="text-green-700">
                    Great job! Your code appears to be secure according to the applied OWASP rules.
                  </p>
                </div>
              ) : (
                <Tabs defaultValue="all" className="w-full">
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="all">
                      All ({report.totalVulnerabilities})
                    </TabsTrigger>
                    <TabsTrigger value="critical">
                      Critical ({report.criticalCount})
                    </TabsTrigger>
                    <TabsTrigger value="high">
                      High ({report.highCount})
                    </TabsTrigger>
                    <TabsTrigger value="medium">
                      Medium ({report.mediumCount})
                    </TabsTrigger>
                    <TabsTrigger value="low">
                      Low ({report.lowCount})
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="all" className="space-y-4 mt-6">
                    {vulnerabilitiesToShow.map((vulnerability) => (
                      <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                    ))}
                    
                    {remainingCount > 0 && !showAllVulnerabilities && (
                      <Button
                        variant="outline"
                        className="w-full"
                        onClick={() => setShowAllVulnerabilities(true)}
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        Show {remainingCount} More Vulnerabilities
                      </Button>
                    )}
                  </TabsContent>

                  <TabsContent value="critical" className="space-y-4 mt-6">
                    {report.vulnerabilities
                      .filter(v => v.severity === 'critical')
                      .map((vulnerability) => (
                        <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                      ))}
                  </TabsContent>

                  <TabsContent value="high" className="space-y-4 mt-6">
                    {report.vulnerabilities
                      .filter(v => v.severity === 'high')
                      .map((vulnerability) => (
                        <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                      ))}
                  </TabsContent>

                  <TabsContent value="medium" className="space-y-4 mt-6">
                    {report.vulnerabilities
                      .filter(v => v.severity === 'medium')
                      .map((vulnerability) => (
                        <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                      ))}
                  </TabsContent>

                  <TabsContent value="low" className="space-y-4 mt-6">
                    {report.vulnerabilities
                      .filter(v => v.severity === 'low')
                      .map((vulnerability) => (
                        <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                      ))}
                  </TabsContent>
                </Tabs>
              )}
            </TabsContent>

            <TabsContent value="graphs" className="mt-6">
              <GraphViewer 
                cfg={report.cfg}
                dfg={report.dfg}
                filename={`analysis-${jobId}`}
              />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Privacy Notice */}
      <Card className="bg-blue-50 border border-blue-200">
        <CardContent className="p-4">
          <div className="flex items-center text-blue-800">
            <Shield className="w-5 h-5 mr-2" />
            <span className="text-sm">
              All analysis is performed locally. Your code is not stored or transmitted to external servers.
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}