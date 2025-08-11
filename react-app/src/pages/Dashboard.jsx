// src/pages/Dashboard.jsx
import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import {
  FolderIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  ClockIcon
} from "@heroicons/react/24/outline";

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalProjects: 0,
    totalScans: 0,
    criticalIssues: 0,
    lastScanDate: null
  });

  const [recentActivity, setRecentActivity] = useState([]);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      // Fetch projects
      const projectsRes = await axios.get("/api/projects");
      const projects = projectsRes.data || [];
      
      // You can add more API calls here for scans and issues
      setStats({
        totalProjects: projects.length,
        totalScans: 12, // Mock data - replace with real API call
        criticalIssues: 5, // Mock data - replace with real API call
        lastScanDate: new Date().toISOString()
      });

      // Mock recent activity - replace with real API call
      setRecentActivity([
        { id: 1, action: "Scan completed", project: "Web App Security", time: "2 hours ago" },
        { id: 2, action: "New project created", project: "Mobile App", time: "1 day ago" },
        { id: 3, action: "Critical issue found", project: "API Gateway", time: "2 days ago" },
      ]);
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
    }
  };

  const StatCard = ({ title, value, icon: Icon, color, change }) => (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
          {change && (
            <p className={`text-xs ${change > 0 ? 'text-green-600' : 'text-red-600'}`}>
              {change > 0 ? '+' : ''}{change}% from last week
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          {Icon && <Icon className="w-6 h-6 text-white" />}
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-lg p-6 text-white">
        <h1 className="text-2xl font-bold mb-2">Welcome back!</h1>
        <p className="text-blue-100">
          Monitor your security scans and manage your projects from this dashboard.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Projects"
          value={stats.totalProjects}
          icon={FolderIcon}
          color="bg-blue-500"
          change={12}
        />
        <StatCard
          title="Total Scans"
          value={stats.totalScans}
          icon={DocumentTextIcon}
          color="bg-green-500"
          change={8}
        />
        <StatCard
          title="Critical Issues"
          value={stats.criticalIssues}
          icon={ExclamationTriangleIcon}
          color="bg-red-500"
          change={-15}
        />
        <StatCard
          title="Security Score"
          value="85%"
          icon={ShieldCheckIcon}
          color="bg-purple-500"
          change={5}
        />
      </div>

      {/* Charts and Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart Placeholder */}
        <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Security Trends</h3>
          <div className="h-64 bg-gray-50 rounded-lg flex items-center justify-center">
            <div className="text-center">
              <ChartBarIcon className="w-12 h-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500">Chart visualization coming soon</p>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Recent Activity</h3>
          <div className="space-y-4">
            {recentActivity.map((activity) => (
              <div key={activity.id} className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-900">{activity.action}</p>
                  <p className="text-sm text-gray-500">{activity.project}</p>
                  <p className="text-xs text-gray-400 flex items-center mt-1">
                    <ClockIcon className="w-3 h-3 mr-1" />
                    {activity.time}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            to="/projects"
            className="flex items-center space-x-3 p-4 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
          >
            <FolderIcon className="w-6 h-6 text-blue-600" />
            <span className="font-medium text-blue-900">Create New Project</span>
          </Link>
          <Link
            to="/reports"
            className="flex items-center space-x-3 p-4 bg-green-50 hover:bg-green-100 rounded-lg transition-colors"
          >
            <DocumentTextIcon className="w-6 h-6 text-green-600" />
            <span className="font-medium text-green-900">View Reports</span>
          </Link>
          <button className="flex items-center space-x-3 p-4 bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors">
            <ShieldCheckIcon className="w-6 h-6 text-purple-600" />
            <span className="font-medium text-purple-900">Security Settings</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;