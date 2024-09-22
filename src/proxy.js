const axios = require('axios');
const pick = require('lodash').pick;
const zlib = require('node:zlib');
const lzma = require('lzma-native');
const ZstdCodec = require('zstd-codec').ZstdCodec;
const shouldCompress = require('./shouldCompress');
const redirect = require('./redirect');
const compress = require('./compress');
const bypass = require('./bypass');
const copyHeaders = require('./copyHeaders');

function urlContainsDomain(url, domain) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname.includes(domain);
  } catch (error) {
    console.error("Invalid URL:", error);
    return false;
  }
}

// Decompression utility function
async function decompress(data, encoding) {
    switch (encoding) {
        case 'gzip':
            return zlib.promises.gunzip(data);
        case 'br':
            return zlib.promises.brotliDecompress(data);
        case 'deflate':
            return zlib.promises.inflate(data);
        case 'lzma':
        case 'lzma2': // LZMA and LZMA2 are handled the same way
            return new Promise((resolve, reject) => {
                lzma.decompress(data, (result, error) => {
                    if (error) return reject(error);
                    resolve(result);
                });
            });
        case 'zstd':
            return new Promise((resolve, reject) => {
                ZstdCodec.run(zstd => {
                    try {
                        const simple = new zstd.Simple();
                        resolve(simple.decompress(data));
                    } catch (error) {
                        reject(error);
                    }
                });
            });
        default:
            console.warn(`Unknown content-encoding: ${encoding}`);
            return data;
    }
}

async function proxy(req, res) {

    if (urlContainsDomain(req.params.url, process.env.DOMAIN)) {
      console.log('Good');
   } else {
      return;
    } 
    
    const config = {
        url: req.params.url,
        method: 'get',
        headers: {
            ...pick(req.headers, ['cookie', 'dnt', 'referer']),
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate, br, lzma, lzma2, zstd',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'DNT': '1',
            'x-forwarded-for': req.headers['x-forwarded-for'] || req.ip,
            via: '2.0 bandwidth-hero',
        },
        timeout: 10000,
        maxRedirects: 5,
        auth: {
            username: process.env.USER,
            password: process.env.PASS
        },
        responseType: 'arraybuffer',
        validateStatus: status => status < 500,
    };

    try {
        const origin = await axios(config);

        // Copy relevant headers from origin to response
        copyHeaders(origin, res);

        // Decompress data based on content-encoding, if necessary
        const contentEncoding = origin.headers['content-encoding'];
        let data = origin.data;
        if (contentEncoding) {
            data = await decompress(data, contentEncoding);
        }

        // Set required response headers and other parameters
        res.setHeader('content-encoding', 'identity');
        req.params.originType = origin.headers['content-type'] || '';
        req.params.originSize = data.length;

        // Decide whether to compress or bypass
        if (shouldCompress(req, data)) {
            compress(req, res, data);
        } else {
            bypass(req, res, data);
        }
    } catch (error) {
        if (error.response) {
            console.error('Server responded with status:', error.response.status);
        } else if (error.request) {
            console.error('No response received:', error.request);
        } else {
            console.error('Error setting up request:', error.message);
        }
        redirect(req, res); // Handle the error by redirecting
    }
}

module.exports = proxy;
