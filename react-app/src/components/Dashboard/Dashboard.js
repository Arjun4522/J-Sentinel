import React, { useState, useEffect } from 'react';
import { Box, Typography, Grid, Card, CardContent, CircularProgress } from '@mui/material';
import axios from 'axios';
import ScanHistory from './ScanHistory';
import ScanStatistics from './ScanStatistics';
import RecentScans from './RecentScans';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const auth = localStorage.getItem('auth');
        const [scansRes, historyRes] = await Promise.all([
          axios.get('http://localhost:8080/api/scans', {
            headers: { Authorization: `Basic ${auth}` }
          }),
          axios.get('http://localhost:8080/api/history/scans', {
            headers: { Authorization: `Basic ${auth}` }
          })
        ]);
        
        const scans = scansRes.data;
        const history = historyRes.data;
        
        // Calculate statistics
        const totalScans = scans.length;
        const totalVulnerabilities = scans.reduce((sum, scan) => sum + (scan.vulnerabilitiesFound || 0), 0);
        const avgFilesPerScan = scans.length > 0 
          ? scans.reduce((sum, scan) => sum + (scan.filesProcessed || 0), 0) / scans.length 
          : 0;
        
        setStats({
          totalScans,
          totalVulnerabilities,
          avgFilesPerScan: Math.round(avgFilesPerScan)
        });
        setLoading(false);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        setLoading(false);
      }
    };
    
    fetchData();
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      
      {stats && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6">Total Scans</Typography>
                <Typography variant="h3">{stats.totalScans}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6">Vulnerabilities Found</Typography>
                <Typography variant="h3">{stats.totalVulnerabilities}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6">Avg Files/Scan</Typography>
                <Typography variant="h3">{stats.avgFilesPerScan}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <ScanHistory />
        </Grid>
        <Grid item xs={12} md={4}>
          <RecentScans />
        </Grid>
      </Grid>
      
      <Box sx={{ mt: 4 }}>
        <ScanStatistics />
      </Box>
    </Box>
  );
};

export default Dashboard;