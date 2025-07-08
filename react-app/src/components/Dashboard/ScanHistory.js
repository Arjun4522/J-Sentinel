import React, { useState, useEffect } from 'react';
import { Box, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import axios from 'axios';

const ScanHistory = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const auth = localStorage.getItem('auth');
        const response = await axios.get('http://localhost:8080/api/history/scans', {
          headers: { Authorization: `Basic ${auth}` }
        });
        setHistory(response.data);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching scan history:', error);
        setLoading(false);
      }
    };
    
    fetchHistory();
  }, []);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan History
      </Typography>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Scan ID</TableCell>
              <TableCell>Source Directory</TableCell>
              <TableCell>Files Processed</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Timestamp</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} align="center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : history.length > 0 ? (
              history.map((scan) => (
                <TableRow key={scan.scanId}>
                  <TableCell>{scan.scanId.substring(0, 8)}...</TableCell>
                  <TableCell>{scan.sourceDirectory}</TableCell>
                  <TableCell>{scan.filesProcessed}</TableCell>
                  <TableCell>{scan.vulnerabilitiesFound}</TableCell>
                  <TableCell>{new Date(scan.timestamp).toLocaleString()}</TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={5} align="center">
                  No scan history available
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default ScanHistory;