// src/pages/ScannedReports.jsx
import { useState, useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import axios from "axios";
import {
  DocumentTextIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  ArrowDownTrayIcon,
  EyeIcon,
  CalendarIcon,
  ShieldExclamationIcon,
  InformationCircleIcon
} from "@heroicons/react/24/outline";

const ScannedReports = () => {
  const [searchParams] = useSearchParams();
  const [reports, setReports] = useState([]);
  const [filteredReports, setFilteredReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  useEffect(() => {
    fetchReports();
  }, []);

  useEffect(() => {
    filterReports();
  }, [reports, searchTerm, statusFilter, severityFilter]);

  const fetchReports = async () => {
    try {
      const res = await axios.get("/api/scans");
      const reportsData = res.data || [];
      setReports(reportsData);
      
      // If there's a scanId in query params, filter to that scan
      const scanId = searchParams.get('scanId');
      if (scanId) {
        const filteredByScan = reportsData.filter(report => report.scanId === scanId);
        setFilteredReports(filteredByScan);
      }
    } catch (error) {
      console.error("Failed to fetch reports:", error);
    } finally {
      setLoading(false);
    }
  };

  const filterReports = () => {
    let filtered = reports;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(report =>
        report.projectName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        report.scanId?.toString().includes(searchTerm)
      );
    }

    // Status filter
    if (statusFilter !== "all") {
      filtered = filtered.filter(report => report.status === statusFilter);
    }

    // Severity filter
    if (severityFilter !== "all") {
      filtered = filtered.filter(report => report.severity === severityFilter);
    }

    setFilteredReports(filtered);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'running':
        return <ClockIcon className="w-5 h-5 text-blue-500" />;
      case 'failed':
        return <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <ClockIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ShieldExclamationIcon className="w-5 h-5 text-red-600" />;
      case 'high':
        return <ExclamationTriangleIcon className="w-5 h-5 text-orange-600" />;
      case 'medium':
        return <InformationCircleIcon className="w-5 h-5 text-yellow-600" />;
      case 'low':
        return <CheckCircleIcon className="w-5 h-5 text-green-600" />;
      default:
        return <InformationCircleIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scanned Reports</h1>
          <p className="text-gray-600">View and manage your security scan results</p>
        </div>
        <div className="flex items-center space-x-3">
          <button className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors">
            <ArrowDownTrayIcon className="w-5 h-5" />
            <span>Export All</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <DocumentTextIcon className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-gray-600">Total Reports</p>
              <p className="text-2xl font-bold text-gray-900">{reports.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <ShieldExclamationIcon className="w-8 h-8 text-red-600" />
            <div>
              <p className="text-sm text-gray-600">Critical Issues</p>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter(r => r.severity === 'critical').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <CheckCircleIcon className="w-8 h-8 text-green-600" />
            <div>
              <p className="text-sm text-gray-600">Completed</p>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter(r => r.status === 'completed').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <ClockIcon className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-gray-600">Running</p>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter(r => r.status === 'running').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-64">
            <div className="relative">
              <MagnifyingGlassIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <FunnelIcon className="w-5 h-5 text-gray-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Reports List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="divide-y divide-gray-200">
          {filteredReports.length === 0 ? (
            <div className="p-12 text-center">
              <DocumentTextIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No reports found</h3>
              <p className="text-gray-600">Try adjusting your filters or start a new scan</p>
            </div>
          ) : (
            filteredReports.map((report) => (
              <ReportItem
                key={`${report.scanId}-${report.projectId}`}
                report={report}
                getStatusIcon={getStatusIcon}
                getSeverityIcon={getSeverityIcon}
                getSeverityColor={getSeverityColor}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const ReportItem = ({ report, getStatusIcon, getSeverityIcon, getSeverityColor }) => {
  // Mock data - replace with actual report data
  const mockReport = {
    scanId: report.scanId || Math.floor(Math.random() * 1000),
    projectName: report.projectName || 'Sample Project',
    status: report.status || 'completed',
    severity: report.severity || 'medium',
    issuesFound: report.issuesFound || Math.floor(Math.random() * 20),
    createdAt: report.createdAt || new Date().toISOString(),
    duration: report.duration || '2m 45s',
    ...report
  };

  return (
    <div className="p-6 hover:bg-gray-50 transition-colors">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          {getStatusIcon(mockReport.status)}
          <div>
            <div className="flex items-center space-x-3">
              <h3 className="font-medium text-gray-900">
                {mockReport.projectName} - Scan #{mockReport.scanId}
              </h3>
              <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(mockReport.severity)}`}>
                {getSeverityIcon(mockReport.severity)}
                {mockReport.severity}
              </span>
            </div>
            <div className="flex items-center space-x-4 text-sm text-gray-500 mt-1">
              <span className="flex items-center">
                <CalendarIcon className="w-4 h-4 mr-1" />
                {new Date(mockReport.createdAt).toLocaleDateString()}
              </span>
              <span>{mockReport.issuesFound} issues found</span>
              <span>Duration: {mockReport.duration}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <button className="flex items-center space-x-2 px-3 py-1 text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-md transition-colors">
            <EyeIcon className="w-4 h-4" />
            <span>View Report</span>
          </button>
          <button className="flex items-center space-x-2 px-3 py-1 text-sm text-gray-600 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors">
            <ArrowDownTrayIcon className="w-4 h-4" />
            <span>Download</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScannedReports;