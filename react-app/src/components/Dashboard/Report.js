// src/components/Dashboard/Report.js
import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Box,
  Typography,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
} from '@mui/material';
import { ArrowBack } from '@mui/icons-material';
import axios from 'axios';

const Report = () => {
  const { scanId } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const auth = localStorage.getItem('auth');
        if (!auth) {
          throw new Error('Authentication token not found');
        }
        const response = await axios.get(`http://localhost:8080/api/scans/${scanId}/report`, {
          headers: { Authorization: `Basic ${auth}` },
        });
        setReport(response.data);
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch report');
        console.error('Report fetch error:', err.response || err);
        setLoading(false);
      }
    };
    fetchReport();
  }, [scanId]);

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'success';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ ml: 2 }}>Loading Report...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography color="error">{error}</Typography>
        <Button component={Link} to="/reports" startIcon={<ArrowBack />} sx={{ mt: 2 }}>
          Back to Reports
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Button component={Link} to="/reports" startIcon={<ArrowBack />} sx={{ mb: 2 }}>
        Back to Reports
      </Button>
      <Typography variant="h4" gutterBottom>Scan Report: {scanId.substring(0, 8)}...</Typography>
      {report && (
        <Box sx={{ mt: 2 }}>
          <Paper sx={{ p: 2, mb: 2 }}>
            <Typography variant="subtitle1">
              Total Vulnerabilities: {report.summary?.total_vulnerabilities || 'N/A'}
            </Typography>
            <Typography variant="subtitle1">
              Severity Breakdown: High: {report.summary?.severity_breakdown?.HIGH || 0}, Medium: {report.summary?.severity_breakdown?.MEDIUM || 0}, Low: {report.summary?.severity_breakdown?.LOW || 0}
            </Typography>
            <Typography variant="subtitle1">
              Scan Duration: {(report.statistics?.scan_duration / 1000000000).toFixed(2) || 'N/A'} seconds
            </Typography>
          </Paper>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>File:Line</TableCell>
                  <TableCell>Rule ID</TableCell>
                  <TableCell>Details</TableCell>
                  <TableCell>Remediation</TableCell>
                  <TableCell>CWE</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Array.isArray(report.vulnerabilities) && report.vulnerabilities.length > 0 ? (
                  report.vulnerabilities.map((vuln, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Chip label={vuln.severity || 'N/A'} color={getSeverityColor(vuln.severity)} size="small" />
                      </TableCell>
                      <TableCell>{vuln.location || 'N/A'}</TableCell>
                      <TableCell>{vuln.rule_id || 'N/A'}</TableCell>
                      <TableCell>{vuln.details || 'N/A'}</TableCell>
                      <TableCell>{vuln.remediation || 'N/A'}</TableCell>
                      <TableCell>{vuln.cwe_id || 'N/A'}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} align="center">No vulnerabilities found</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Box>
  );
};

export default Report;