// server.js
const express = require('express');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main HTML file at the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'rdpmon.html'));
});
// Endpoint to fetch logs using the PowerShell script
app.get('/api/logs', (req, res) => {
    console.log("Fetching logs..."); // Log the fetch attempt
    exec('powershell.exe -File "./scripts/Advance Siem_security log export_present.ps1"', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error executing PowerShell: ${error.message}`);
            return res.status(500).send(`Error: ${error.message}`);
        }
        if (stderr) {
            console.error(`PowerShell stderr: ${stderr}`);
            return res.status(500).send(`Stderr: ${stderr}`);
        }

        // Log the output to verify PowerShell output
        console.log("PowerShell output:", stdout);
        
        // Assuming PowerShell outputs JSON data
        try {
            const data = JSON.parse(stdout);
            res.json(data);
        } catch (parseError) {
            console.error("JSON parse error:", parseError.message);
            res.status(500).send('Failed to parse PowerShell output.');
        }
    });
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
