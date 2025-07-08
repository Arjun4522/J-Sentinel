import React, { useState, useEffect } from 'react';
import { Box, Typography } from '@mui/material';
import { Bar } from 'react-chartjs-2';
import axios from 'axios';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const ScanStatistics = () => {
  const [chartData, setChartData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const auth = localStorage.getItem('auth');
        const response = await axios.get('http://localhost:8080/api/history/scans', {
          headers: { Authorization: `Basic ${auth}` }
        });
        
        const history = response.data;
        if (history.length > 0) {
          // Group by source directory
          const directoryStats = history.reduce((acc, scan) => {
            const dir = scan.sourceDirectory;
            if (!acc[dir]) {
              acc[dir] = { scans: 0, vulnerabilities: 0 };
            }
            acc[dir].scans += 1;
            acc[dir].vulnerabilities += scan.vulnerabilitiesFound;
            return acc;
          }, {});
          
          const directories = Object.keys(directoryStats);
          const vulnerabilities = directories.map(dir => directoryStats[dir].vulnerabilities);
          
          setChartData({
            labels: directories,
            datasets: [
              {
                label: 'Vulnerabilities Found',
                data: vulnerabilities,
                backgroundColor: 'rgba(255, 99, 132, 0.5)',
              }
            ]
          });
        }
      } catch (error) {
        console.error('Error fetching statistics data:', error);
      }
    };
    
    fetchData();
  }, []);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan Statistics
      </Typography>
      {chartData ? (
        <Box sx={{ height: 400 }}>
          <Bar 
            data={chartData}
            options={{
              responsive: true,
              plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Vulnerabilities by Directory' }
              }
            }}
          />
        </Box>
      ) : (
        <Typography>No statistics data available</Typography>
      )}
    </Box>
  );
};

export default ScanStatistics;