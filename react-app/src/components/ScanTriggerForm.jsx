// src/components/ScanTriggerForm.jsx
import { useState } from 'react';
import axios from 'axios';
import { FolderIcon, DocumentIcon, PlayIcon } from '@heroicons/react/24/outline';

const ScanTriggerForm = ({ projectId, onScanTriggered }) => {
  const [sourceDir, setSourceDir] = useState('');
  const [rulesDir, setRulesDir] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post('/api/scans', { 
        projectId, 
        sourceDir, 
        rulesDir, 
        scanType 
      });
      console.log('Scan started:', response.data);
      onScanTriggered?.();
      
      // Reset form
      setSourceDir('');
      setRulesDir('');
      setScanType('full');
    } catch (err) {
      console.error('Scan failed', err);
      alert('Failed to start scan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleScan} className="space-y-6">
      <div>
        <label htmlFor="scanType" className="block text-sm font-medium text-gray-700 mb-2">
          Scan Type
        </label>
        <select
          id="scanType"
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        >
          <option value="full">Full Security Scan</option>
          <option value="quick">Quick Scan</option>
          <option value="vulnerability">Vulnerability Assessment</option>
          <option value="compliance">Compliance Check</option>
        </select>
      </div>

      <div>
        <label htmlFor="sourceDir" className="block text-sm font-medium text-gray-700 mb-2">
          Source Directory
        </label>
        <div className="relative">
          <FolderIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
          <input
            type="text"
            id="sourceDir"
            placeholder="Enter source directory path"
            value={sourceDir}
            onChange={(e) => setSourceDir(e.target.value)}
            required
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
        <p className="text-xs text-gray-500 mt-1">
          Path to the source code directory to scan
        </p>
      </div>

      <div>
        <label htmlFor="rulesDir" className="block text-sm font-medium text-gray-700 mb-2">
          Rules Directory
        </label>
        <div className="relative">
          <DocumentIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
          <input
            type="text"
            id="rulesDir"
            placeholder="Enter rules directory path"
            value={rulesDir}
            onChange={(e) => setRulesDir(e.target.value)}
            required
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
        <p className="text-xs text-gray-500 mt-1">
          Path to the custom rules directory (optional)
        </p>
      </div>

      <div className="bg-gray-50 rounded-lg p-4">
        <h4 className="text-sm font-medium text-gray-900 mb-2">Scan Configuration</h4>
        <div className="space-y-2 text-sm text-gray-600">
          <div className="flex justify-between">
            <span>Project ID:</span>
            <span className="font-mono">{projectId}</span>
          </div>
          <div className="flex justify-between">
            <span>Scan Type:</span>
            <span className="capitalize">{scanType}</span>
          </div>
          <div className="flex justify-between">
            <span>Estimated Duration:</span>
            <span>{scanType === 'quick' ? '5-10 min' : '15-30 min'}</span>
          </div>
        </div>
      </div>

      <div className="flex justify-end space-x-3">
        <button
          type="button"
          onClick={() => onScanTriggered?.()}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors disabled:opacity-50"
        >
          <PlayIcon className="w-4 h-4" />
          <span>{loading ? 'Starting...' : 'Start Scan'}</span>
        </button>
      </div>
    </form>
  );
};

export default ScanTriggerForm;