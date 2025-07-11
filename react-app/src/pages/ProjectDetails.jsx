// src/pages/ProjectDetails.jsx
import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import ScanTriggerForm from "../components/ScanTriggerForm";
import Modal from "../components/Modal";
import axios from "axios";
import {
  ArrowLeftIcon,
  PlayIcon,
  DocumentTextIcon,
  CalendarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  FolderIcon,
  TrashIcon
} from "@heroicons/react/24/outline";

function ProjectDetails() {
  const { id: projectId } = useParams();
  const [project, setProject] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showScanModal, setShowScanModal] = useState(false);

  useEffect(() => {
    fetchProjectDetails();
    fetchScans();
  }, [projectId]);

  const fetchProjectDetails = async () => {
    try {
      const res = await axios.get(`/api/projects/${projectId}`);
      setProject(res.data);
    } catch (error) {
      console.error("Failed to fetch project details:", error);
    }
  };

  const fetchScans = async () => {
    try {
      const res = await axios.get(`/api/scans/project/${projectId}`);
      setScans(res.data || []);
    } catch (error) {
      console.error("Failed to fetch scans:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (window.confirm("Are you sure you want to delete this scan?")) {
      try {
        await axios.delete(`/api/scans/${scanId}`);
        fetchScans();
      } catch (error) {
        console.error("Failed to delete scan:", error);
      }
    }
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

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'running':
        return 'bg-blue-100 text-blue-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
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
        <div className="flex items-center space-x-4">
          <Link
            to="/projects"
            className="p-2 text-gray-600 hover:text-gray-900 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <ArrowLeftIcon className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              {project?.name || 'Project Details'}
            </h1>
            <p className="text-gray-600">{project?.description || 'No description'}</p>
          </div>
        </div>
        <button
          onClick={() => setShowScanModal(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <PlayIcon className="w-5 h-5" />
          <span>Start New Scan</span>
        </button>
      </div>

      {/* Project Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <FolderIcon className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-gray-600">Total Scans</p>
              <p className="text-2xl font-bold text-gray-900">{scans.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <CheckCircleIcon className="w-8 h-8 text-green-600" />
            <div>
              <p className="text-sm text-gray-600">Completed</p>
              <p className="text-2xl font-bold text-gray-900">
                {scans.filter(s => s.status === 'completed').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center space-x-3">
            <ExclamationTriangleIcon className="w-8 h-8 text-red-600" />
            <div>
              <p className="text-sm text-gray-600">Issues Found</p>
              <p className="text-2xl font-bold text-gray-900">
                {scans.reduce((acc, scan) => acc + (scan.issuesCount || 0), 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Scans List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Scan History</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {scans.length === 0 ? (
            <div className="p-12 text-center">
              <DocumentTextIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No scans yet</h3>
              <p className="text-gray-600 mb-4">Start your first security scan for this project</p>
              <button
                onClick={() => setShowScanModal(true)}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Start Scan
              </button>
            </div>
          ) : (
            scans.map((scan) => (
              <ScanItem
                key={scan.scanId}
                scan={scan}
                onDelete={handleDeleteScan}
                getStatusIcon={getStatusIcon}
                getStatusColor={getStatusColor}
              />
            ))
          )}
        </div>
      </div>

      {/* Scan Modal */}
      <Modal
        isOpen={showScanModal}
        onClose={() => setShowScanModal(false)}
        title="Start New Scan"
        size="md"
      >
        <ScanTriggerForm
          projectId={projectId}
          onScanTriggered={() => {
            setShowScanModal(false);
            fetchScans();
          }}
        />
      </Modal>
    </div>
  );
}

const ScanItem = ({ scan, onDelete, getStatusIcon, getStatusColor }) => {
  return (
    <div className="p-6 hover:bg-gray-50 transition-colors">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          {getStatusIcon(scan.status)}
          <div>
            <h3 className="font-medium text-gray-900">
              Scan #{scan.scanId}
            </h3>
            <div className="flex items-center space-x-4 text-sm text-gray-500">
              <span className="flex items-center">
                <CalendarIcon className="w-4 h-4 mr-1" />
                {new Date(scan.createdAt || Date.now()).toLocaleDateString()}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                {scan.status || 'pending'}
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Link
            to={`/reports?scanId=${scan.scanId}`}
            className="text-blue-600 hover:text-blue-700 text-sm font-medium"
          >
            View Report
          </Link>
          <button
            onClick={() => onDelete(scan.scanId)}
            className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-md transition-colors"
          >
            <TrashIcon className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ProjectDetails;