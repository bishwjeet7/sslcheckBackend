const express = require('express');
const tls = require('tls');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { X509Certificate } = require('crypto');
const app = express();

const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

app.use(cors({
  origin: '*',
  methods: ['POST'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});
app.use('/api/', limiter);


/**
 * Sanitizes the domain input by removing protocol and trailing slashes.
 * @param {string} input - The user-provided domain input.
 * @returns {string} - The sanitized domain.
 */
const sanitizeDomain = (input) => {
  let sanitized = input.trim();
  // Remove protocol (http:// or https://)
  sanitized = sanitized.replace(/(^\w+:|^)\/\//, '');
  // Remove trailing slash
  sanitized = sanitized.replace(/\/$/, '');
  return sanitized;
};

/**
 * Validates the domain format.
 * @param {string} domain - The domain to validate.
 * @returns {boolean} - True if valid, else false.
 */
const isValidDomain = (domain) => {
  const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,11}?$/;
  return domainRegex.test(domain);
};

/**
 * Determines the public key type from the certificate.
 * @param {X509Certificate} cert - The parsed certificate.
 * @returns {string} - The public key type (e.g., RSA, ECDSA).
 */
const getPublicKeyType = (cert) => {
    try {
      const pubKey = cert.publicKey;
      if (!pubKey) return 'Unknown';
  
      const keyType = pubKey.asymmetricKeyType;
      if (!keyType) return 'Unknown';
  
      switch (keyType) {
        case 'rsa':
          return 'RSA';
        case 'ec':
          return 'ECDSA';
        case 'ed25519':
          return 'ED25519';
        case 'ed448':
          return 'ED448';
        default:
          return keyType.toUpperCase();
      }
    } catch (error) {
      console.error('Error determining public key type:', error.message);
      return 'Unknown';
    }
  };


app.post('/api/check-certificate', async (req, res) => {
  let { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Domain is required.' });
  }

  domain = sanitizeDomain(domain);

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Invalid domain format.' });
  }

  try {
    const options = {
      host: domain,
      port: 443,
      method: 'GET',
      rejectUnauthorized: false,
      timeout: 5000,
      servername: domain,
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();

      if (!cert || Object.keys(cert).length === 0) {
        return res.status(400).json({ error: 'No certificate found.' });
      }

      try {
        const rawCertDer = cert.raw.toString('binary');
        const rawCertBuffer = Buffer.from(rawCertDer, 'binary');

        const x509 = new X509Certificate(rawCertBuffer);

        const now = new Date();
        const validityStatus = now >= x509.validFrom && now <= x509.validTo;
        const expirationDate = x509.validTo;

        const issuerDetails = x509.issuer;
        const subjectDetails = x509.subject;

        let validForDomain = false;
        const san = x509.subjectAltName;

        if (san) {
          const domains = san.match(/DNS:([^,]+)/g).map(d => d.replace('DNS:', '').trim());
          validForDomain = domains.includes(domain) || domains.some(d => {
            if (d.startsWith('*')) {
              const wildcardBase = d.slice(1);
              return domain.endsWith(wildcardBase);
            }
            return false;
          });
        } else {
          const cn = x509.commonName;
          if (cn.startsWith('*')) {
            const wildcardBase = cn.slice(1);
            validForDomain = domain.endsWith(wildcardBase);
          } else {
            validForDomain = cn === domain;
          }
        }

        const caIsValid = !!x509.issuer.commonName;

        const notSelfSigned = x509.issuer !== x509.subject;

        const publicKeyType = getPublicKeyType(x509);

        const crlOcspStatus = 'Revocation status check not implemented.';

        const result = {
          validityStatus,
          expirationDate,
          issuerDetails,
          subjectDetails,
          validForDomain,
          caIsValid,
          notSelfSigned,
          publicKeyType,
          crlOcspStatus,
        };

        return res.json(result);
      } catch (parseError) {
        console.error('Certificate Parsing Error:', parseError.message);
        return res.status(500).json({ error: 'Failed to parse the certificate.' });
      }
    });

    socket.on('error', (err) => {
      console.error(`TLS Connection Error for domain ${domain}:`, err.message);
      return res.status(500).json({ error: `Failed to connect to the domain: ${err.message}` });
    });

    socket.on('timeout', () => {
      console.error(`TLS Connection Timeout for domain ${domain}`);
      socket.destroy();
      return res.status(500).json({ error: 'Connection timed out.' });
    });
  } catch (error) {
    console.error(`Unexpected Error for domain ${domain}:`, error);
    return res.status(500).json({ error: 'An error occurred while checking the certificate.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
