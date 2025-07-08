import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  List, 
  ListItem, 
  ListItemText, 
  Divider,
  Paper // Add this import
} from '@mui/material';
import axios from 'axios';

const RecentScans = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchRecentScans = async () => {
      try {
        const auth = localStorage.getItem('auth');
        const response = await axios.get('http://localhost:8080/api/scans', {
          headers: { Authorization: `Basic ${auth}` }
        });
        // Sort by startTime and get latest 5
        const sortedScans = response.data.sort((a, b) => b.startTime - a.startTime).slice(0, 5);
        setScans(sortedScans);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching recent scans:', error);
        setLoading(false);
      }
    };
    
    fetchRecentScans();
  }, []);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Recent Scans
      </Typography>
      {loading ? (
        <Typography>Loading...</Typography>
      ) : scans.length > 0 ? (
        <List component={Paper}>
          {scans.map((scan, index) => (
            <React.Fragment key={scan.scanId}>
              <ListItem>
                <ListItemText
                  primary={scan.sourceDir}
                  secondary={`Status: ${scan.status} - ${scan.vulnerabilitiesFound} vulnerabilities`}
                />
              </ListItem>
              {index < scans.length - 1 && <Divider />}
            </React.Fragment>
          ))}
        </List>
      ) : (
        <Typography>No recent scans available</Typography>
      )}
    </Box>
  );
};

export default RecentScans;