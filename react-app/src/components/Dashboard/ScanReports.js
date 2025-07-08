// src/components/Dashboard/ScanReports.js
import React, { useState, useEffect } from 'react';
import { Box, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Link } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import axios from 'axios';

const ScanReports = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const auth = localStorage.getItem('auth');
        if (!auth) {
          throw new Error('Authentication token not found');
        }
        const response = await axios.get('http://localhost:8080/api/scans', {
          headers: { Authorization: `Basic ${auth}` },
        });
        setScans(response.data.sort((a, b) => b.startTime - a.startTime));
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch scans');
        console.error('Error fetching scans:', err.response || err);
        setLoading(false);
      }
    };

    fetchScans();
    const intervalId = setInterval(fetchScans, 30000); // Refresh every 30 seconds
    return () => clearInterval(intervalId);
  }, []);

  if (loading) {
    return <Typography>Loading scans...</Typography>;
  }

  if (error) {
    return <Typography color="error">{error}</Typography>;
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>Scan Reports</Typography>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Scan ID</TableCell>
              <TableCell>Source Directory</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Timestamp</TableCell>
              <TableCell>View Report</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {scans.length > 0 ? (
              scans.map((scan) => (
                <TableRow key={scan.scanId}>
                  <TableCell>{scan.scanId.substring(0, 8)}...</TableCell>
                  <TableCell>{scan.sourceDir || 'N/A'}</TableCell>
                  <TableCell>{scan.status || 'N/A'}</TableCell>
                  <TableCell>{scan.vulnerabilitiesFound || 'N/A'}</TableCell>
                  <TableCell>{new Date(scan.startTime).toLocaleString()}</TableCell>
                  <TableCell>
                    {scan.status.toLowerCase() === 'completed' ? (
                      <Link component={RouterLink} to={`/report/${scan.scanId}`}>
                        View Report
                      </Link>
                    ) : (
                      <Typography color="textSecondary">Not Available</Typography>
                    )}
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} align="center">No scans available</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default ScanReports;