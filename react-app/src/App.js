// src/App.js
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Box, Typography, Button } from '@mui/material';
import { Report as ReportIcon, Settings } from '@mui/icons-material'; // Renamed Report to ReportIcon
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard/Dashboard';
import ScanHistory from './components/Dashboard/ScanHistory';
import CreateScan from './components/Dashboard/CreateScan';
import ScanReports from './components/Dashboard/ScanReports';
import Report from './components/Dashboard/Report'; // Component for individual reports
import Layout from './components/Layout/Layout';

const App = () => {
  const [authenticated, setAuthenticated] = useState(!!localStorage.getItem('auth'));

  // Placeholder for ScanHistoryPage
  const ScanHistoryPage = () => (
    <Box>
      <ScanHistory />
    </Box>
  );

  // Placeholder for Configurations
  const Configurations = () => (
    <Box sx={{ textAlign: 'center', py: 8 }}>
      <Settings sx={{ fontSize: 80, color: 'primary.main', mb: 2 }} />
      <Typography variant="h4" gutterBottom>
        Scanner Configuration
      </Typography>
      <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
        Configure scan settings and security parameters
      </Typography>
      <Button variant="contained" startIcon={<Settings />} size="large">
        Open Settings
      </Button>
    </Box>
  );

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login setAuthenticated={setAuthenticated} />} />
        <Route
          path="/dashboard"
          element={
            authenticated ? (
              <Layout>
                <Dashboard />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/create-scan" // Fixed typo from "/createpodman scan"
          element={
            authenticated ? (
              <Layout>
                <CreateScan />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/scan-history"
          element={
            authenticated ? (
              <Layout>
                <ScanHistoryPage />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/reports"
          element={
            authenticated ? (
              <Layout>
                <ScanReports />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/report/:scanId"
          element={
            authenticated ? (
              <Layout>
                <Report />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="/configurations"
          element={
            authenticated ? (
              <Layout>
                <Configurations />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="*"
          element={<Navigate to={authenticated ? '/dashboard' : '/login'} />}
        />
      </Routes>
    </Router>
  );
};

export default App;