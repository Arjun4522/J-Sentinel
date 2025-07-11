// src/pages/Projects.jsx
import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import ProjectForm from "../components/ProjectForm";
import Modal from "../components/Modal";
import axios from "axios";
import {
  PlusIcon,
  FolderIcon,
  EyeIcon,
  TrashIcon,
  DocumentArrowUpIcon,
  CalendarIcon,
  ChevronRightIcon
} from "@heroicons/react/24/outline";

const Projects = () => {
  const [projects, setProjects] = useState([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchProjects = async () => {
    try {
      const res = await axios.get("/api/projects");
      console.log("Fetched projects:", res.data);
      setProjects(res.data || []);
    } catch (err) {
      console.error("Error fetching projects", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleProjectCreated = () => {
    fetchProjects();
  };

  const handleDeleteProject = async (projectId) => {
    if (window.confirm("Are you sure you want to delete this project?")) {
      try {
        await axios.delete(`/api/projects/${projectId}`);
        fetchProjects();
      } catch (err) {
        console.error("Delete failed:", err);
      }
    }
  };

  const handleStartScan = async (projectId, file) => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("projectId", projectId);

    try {
      const res = await axios.post("/api/scan/start", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
      console.log("Scan started:", res.data);
      alert("Scan started successfully!");
    } catch (err) {
      console.error("Failed to start scan:", err);
      alert("Failed to start scan.");
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
          <h1 className="text-2xl font-bold text-gray-900">Projects</h1>
          <p className="text-gray-600">Manage your security scanning projects</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <PlusIcon className="w-5 h-5" />
          <span>New Project</span>
        </button>
      </div>

      {/* Projects Grid */}
      {projects.length === 0 ? (
        <div className="text-center py-12">
          <FolderIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No projects yet</h3>
          <p className="text-gray-600 mb-4">Create your first project to get started</p>
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Create Project
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <ProjectCard
              key={project.projectId}
              project={project}
              onDelete={handleDeleteProject}
              onStartScan={handleStartScan}
            />
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Create New Project"
        size="md"
      >
        <ProjectForm
          onProjectCreated={handleProjectCreated}
          onClose={() => setIsModalOpen(false)}
        />
      </Modal>
    </div>
  );
};

const ProjectCard = ({ project, onDelete, onStartScan }) => {
  const [fileInputKey, setFileInputKey] = useState(Date.now());

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      onStartScan(project.projectId, file);
      // Reset file input
      setFileInputKey(Date.now());
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">{project.name}</h3>
          <p className="text-gray-600 text-sm line-clamp-2">{project.description || "No description"}</p>
        </div>
        <FolderIcon className="w-6 h-6 text-gray-400 flex-shrink-0" />
      </div>

      <div className="flex items-center text-sm text-gray-500 mb-4">
        <CalendarIcon className="w-4 h-4 mr-1" />
        <span>Created {new Date(project.createdAt || Date.now()).toLocaleDateString()}</span>
      </div>

      {/* File Upload */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Upload scan file
        </label>
        <input
          key={fileInputKey}
          type="file"
          onChange={handleFileUpload}
          className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
        />
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <Link
          to={`/projects/${project.projectId}`}
          className="flex items-center space-x-2 text-sm font-medium text-blue-600 hover:text-blue-700"
        >
          <EyeIcon className="w-4 h-4" />
          <span>View Details</span>
          <ChevronRightIcon className="w-4 h-4" />
        </Link>
        <button
          onClick={() => onDelete(project.projectId)}
          className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-md transition-colors"
        >
          <TrashIcon className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

export default Projects;