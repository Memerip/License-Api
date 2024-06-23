const express = require('express');
const uuid = require('uuid');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

const LICENSE_FILE = 'licenses.json';
const LOG_FILE = path.join(__dirname, 'logs.txt');

// Configure whitelist here
const whitelist1 = process.env['root_ip']
const allowedIPs = ['0.0.0.0', '0.0.0.0']; // IPs without replit secrets
// const allowedIPs = [whitelist1]; // Using replit secrets to hide ip

function restrictAccess(req, res, next) {
  const clientIP = getClientIPAddress(req);
  if (allowedIPs.includes(clientIP)) {
    next();
  } else {
    console.log(`Unauthorized Access Attempt: IP ${clientIP} tried to access restricted resource.`);
    return res.status(403).send('Forbidden 403 - Unauthorized IP Address');
  }
}

app.use(bodyParser.json());

app.get('/', restrictAccess, (req, res) => {
  res.sendFile(__dirname + '/html/index.html');
});

app.get('/licenses.json', restrictAccess, (req, res) => {
  res.sendFile(__dirname + '/licenses.json');
});

app.get('/logs.txt', restrictAccess, (req, res) => {
  res.sendFile(__dirname + '/logs.txt');
});

function loadLicenseData() {
  try {
    const data = fs.readFileSync(LICENSE_FILE);
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

function saveLicenseData(licenses) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(licenses, null, 2));
}

function getClientIPAddress(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress;
}

function logToFile(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;

  fs.appendFile(LOG_FILE, logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });
}

app.post('/api/generate-license', restrictAccess, (req, res) => {
  const data = req.body;

  if ('expiration' in data) {
    const expiration = data.expiration;
    let expiration_date = null;

    if (expiration === 'custom') {
      if ('custom_expiration_date' in data) {
        expiration_date = new Date(data.custom_expiration_date);
      } else {
        return res.status(400).json({ error: 'Custom expiration date not provided.' });
      }
    } else if (expiration === '7_days') {
      expiration_date = new Date();
      expiration_date.setDate(expiration_date.getDate() + 7);
    } else if (expiration === '1_month') {
      expiration_date = new Date();
      expiration_date.setMonth(expiration_date.getMonth() + 1);
    }

    const license_key = uuid.v4();
    const licenseData = {
      license_key: license_key,
      expiration_date: expiration_date ? expiration_date.toISOString() : null,
      created_at: new Date().toISOString(),
      ip: ''
    };

    const licenses = loadLicenseData();
    licenses.push(licenseData);
    saveLicenseData(licenses);

    console.log('License Key Generated:', license_key);
    logToFile(`License Key Generated: ${license_key}`);

    if (expiration_date) {
      return res.status(201).json({ message: 'License Key Generated', license_key: license_key, expiration_date: expiration_date });
    } else {
      return res.status(201).json({ message: 'Generated License Key (Lifetime)', license_key: license_key });
    }
  } else {
    return res.status(400).json({ error: 'Expiration not provided.' });
  }
});

app.get('/api/check-license/:key', (req, res) => {
  const key = req.params.key;
  const clientIP = getClientIPAddress(req);

  const licenses = loadLicenseData();
  const licenseData = licenses.find((license) => license.license_key === key);

  if (!licenseData) {
    return res.status(404).json({ error: 'License key not found.' });
  }

  console.log('License Key Check Requested:', key, 'by IP:', clientIP);
  logToFile(`License Key Check Requested: ${key} by IP: ${clientIP}`);

  if (!licenseData.ip) {
    licenseData.ip = clientIP;
    saveLicenseData(licenses);
  } else if (licenseData.ip !== clientIP) {
    console.log(`Key Sharing Detected: IP ${clientIP} tried to check key ${key}`);
    logToFile(`Key Sharing Detected: IP ${clientIP} tried to check key ${key}`);
    return res.status(403).json({ error: 'Key sharing detected. License key invalid.' });
  }

  if (licenseData.expired) {
    return res.status(200).json({ valid: false });
  }

  if (licenseData.expiration_date && new Date() > new Date(licenseData.expiration_date)) {
    licenseData.expired = true;
    saveLicenseData(licenses);

    console.log('License Key Expired:', key);
    logToFile(`License Key Expired: ${key}`);

    return res.status(200).json({ valid: false });
  }

  return res.status(200).json({ valid: true });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});
