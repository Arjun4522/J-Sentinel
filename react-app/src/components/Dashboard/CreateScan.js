import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Typography,
  Button,
  TextField,
  FormControlLabel,
  Checkbox,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import { PlayArrow, Add, Folder } from '@mui/icons-material';
import axios from 'axios';

const CreateScan = () => {
  const [sourceDir, setSourceDir] = useState('');
  const [rulesDir, setRulesDir] = useState('');
  const [timeout, setTimeout] = useState(300);
  const [useSemgrep, setUseSemgrep] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [isPolling, setIsPolling] = useState(false);

  const sourceDirInputRef = useRef(null);
  const rulesDirInputRef = useRef(null);

  const handleDirectorySelect = (setter, inputRef) => (event) => {
    const files = event.target.files;
    if (files.length > 0) {
      const directoryName = files[0].webkitRelativePath.split('/')[0];
      setter(directoryName);
    }
    inputRef.current.value = '';
  };

  const handleSubmit = async () => {
    if (!sourceDir || !rulesDir) {
      setError('Please specify both source and rules directories');
      return;
    }
    setLoading(true);
    setError(null);
    setScanId(null);
    setScanStatus('initiating');
    setReport(null);
    setIsPolling(false);

    const auth = localStorage.getItem('auth');
    if (!auth) {
      setError('You must be logged in to start a scan.');
      setLoading(false);
      return;
    }

    const config = { sourceDir, rulesDir, timeout, useSemgrep };

    try {
      const response = await axios.post(
        'http://localhost:8080/api/scan/trigger',
        config,
        {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Basic ${auth}`,
          },
        }
      );
      const data = response.data;
      setScanId(data.scanId);
      setScanStatus('running');
      setIsPolling(true);
      console.log('Scan initiated:', data.scanId);
    } catch (err) {
      setError('Failed to start scan. Please check your configuration.');
      console.error('Scan initiation error:', err.response || err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isPolling || !scanId) return;
    const intervalId = setInterval(async () => {
      try {
        const auth = localStorage.getItem('auth');
        const response = await axios.get(`http://localhost:8080/api/scans/${scanId}/metadata`, {
          headers: { Authorization: `Basic ${auth}` },
        });
        const data = response.data;
        const status = data.status.toLowerCase();
        setScanStatus(status);
        console.log('Scan status:', status, data);
        if (['completed', 'failed'].includes(status)) {
          setIsPolling(false);
          if (status === 'completed') {
            try {
              const reportResponse = await axios.get(`http://localhost:8080/api/scans/${scanId}/report`, {
                headers: { Authorization: `Basic ${auth}` },
              });
              setReport(reportResponse.data);
              console.log('Report fetched:', reportResponse.data);
            } catch (reportErr) {
              setError('Failed to fetch report');
              console.error('Report fetch error:', reportErr.response || reportErr);
            }
          } else {
            setError('Scan failed');
          }
        }
      } catch (err) {
        setError('Error fetching scan status');
        console.error('Status fetch error:', err.response || err);
        setIsPolling(false);
      }
    }, 5000);
    return () => clearInterval(intervalId);
  }, [isPolling, scanId]);

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'HIGH': return 'error';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  return (
    <Box sx={{ textAlign: 'center', py: 8 }}>
      <PlayArrow sx={{ fontSize: 80, color: 'primary.main', mb: 2 }} />
      <Typography variant="h4" gutterBottom>Create New Scan</Typography>
      <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
        Configure and start a new vulnerability scan
      </Typography>
      <Box sx={{ maxWidth: 800, mx: 'auto' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <TextField
            label="Source Directory"
            value={sourceDir}
            onChange={(e) => setSourceDir(e.target.value)}
            fullWidth
            margin="normal"
            disabled={loading}
            placeholder="Select or type source directory"
          />
          <Button
            variant="outlined"
            startIcon={<Folder />}
            onClick={() => sourceDirInputRef.current.click()}
            disabled={loading}
            sx={{ ml: 2 }}
          >
            Browse
          </Button>
          <input
            type="file"
            webkitdirectory="true"
            directory="true"
            style={{ display: 'none' }}
            ref={sourceDirInputRef}
            onChange={handleDirectorySelect(setSourceDir, sourceDirInputRef)}
          />
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <TextField
            label="Rules Directory"
            value={rulesDir}
            onChange={(e) => setRulesDir(e.target.value)}
            fullWidth
            margin="normal"
            disabled={loading}
            placeholder="Select or type rules directory"
          />
          <Button
            variant="outlined"
            startIcon={<Folder />}
            onClick={() => rulesDirInputRef.current.click()}
            disabled={loading}
            sx={{ ml: 2 }}
          >
            Browse
          </Button>
          <input
            type="file"
            webkitdirectory="true"
            directory="true"
            style={{ display: 'none' }}
            ref={rulesDirInputRef}
            onChange={handleDirectorySelect(setRulesDir, rulesDirInputRef)}
          />
        </Box>
        <TextField
          label="Timeout (seconds)"
          value={timeout}
          onChange={(e) => setTimeout(Number(e.target.value))}
          fullWidth
          margin="normal"
          type="number"
          disabled={loading}
        />
        <FormControlLabel
          control={<Checkbox checked={useSemgrep} onChange={(e) => setUseSemgrep(e.target.checked)} disabled={loading} />}
          label="Use Semgrep Registry"
        />
        <Button
          variant="contained"
          startIcon={<Add />}
          size="large"
          onClick={handleSubmit}
          disabled={loading}
          sx={{ mt: 2 }}
        >
          {loading ? 'Starting Scan...' : 'Start New Scan'}
        </Button>
        {error && <Typography color="error" sx={{ mt: 2 }}>{error}</Typography>}
        {scanId && (
          <Box sx={{ mt: 4 }}>
            <Typography variant="h6">Current Scan Status: {scanStatus}</Typography>
            {scanStatus === 'initiating' && <Typography>Initiating scan...</Typography>}
            {scanStatus === 'running' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CircularProgress size={24} />
                <Typography>Scan is running...</Typography>
              </Box>
            )}
            {scanStatus === 'completed' && report && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="h6">Current Scan Report</Typography>
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
            {scanStatus === 'failed' && <Typography color="error">Scan failed</Typography>}
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default CreateScan;