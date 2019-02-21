import HmacSHA256 from 'crypto-js/hmac-sha256'
import Sha256 from 'crypto-js/sha256'

function getCanonicalRequest(now, host, path, query, headers, method, payload) {
  const canonicalRequest =
    method.toUpperCase() +
    '\n' +
    path +
    '\n' +
    query +
    '\n' +
    Object.keys(headers)
      .map(header => `${header}:${headers[header]}`)
      .join('\n')
      .toLowerCase() +
    (Object.keys(headers).length ? '\n' : '') +
    'host:' +
    host +
    '\n' +
    'x-amz-date:' +
    getFormattedDate(now, 'long') +
    '\n' +
    '\n' +
    Object.keys(headers)
      .join(';')
      .toLowerCase() +
    (Object.keys(headers).length ? ';' : '') +
    'host;x-amz-date' +
    '\n' +
    Sha256(JSON.stringify(payload)).toString()
  return canonicalRequest
}

function getHashedCanonicalRequest(request) {
  return Sha256(request).toString()
}

function getStringToSign(now, region, service, hashedRequest) {
  const stringToSign =
    'AWS4-HMAC-SHA256' +
    '\n' +
    getFormattedDate(now, 'long') +
    '\n' +
    getFormattedDate(now, 'short') +
    '/' +
    region +
    '/' +
    service +
    '/aws4_request' +
    '\n' +
    hashedRequest
  return stringToSign
}

function getSigningKey(now, region, service, secretAccessKey) {
  const dateStamp = getFormattedDate(now, 'short')
  const kDate = HmacSHA256(dateStamp, 'AWS4' + secretAccessKey)
  const kRegion = HmacSHA256(region, kDate)
  const kService = HmacSHA256(service, kRegion)
  const kSigning = HmacSHA256('aws4_request', kService)
  return kSigning
}

function getSignature(stringToSign, signingKey) {
  return HmacSHA256(stringToSign, signingKey).toString()
}

function getAwsSignature(
  timeStamp,
  host,
  path,
  query,
  headers,
  method,
  region,
  service,
  accessKeyId,
  secretAccessKey,
  payload
) {
  const canonicalRequest = getCanonicalRequest(
    timeStamp,
    host,
    path,
    query,
    headers,
    method,
    payload
  )
  const hashedRequest = getHashedCanonicalRequest(canonicalRequest)
  const stringToSign = getStringToSign(
    timeStamp,
    region,
    service,
    hashedRequest
  )
  const signingKey = getSigningKey(timeStamp, region, service, secretAccessKey)
  const signature = getSignature(stringToSign, signingKey)
  return signature
}

function getFormattedDate(now, format) {
  var month = now.getUTCMonth() + 1
  var day = now.getUTCDate()
  month = month > 9 ? month.toString() : '0' + month.toString()
  day = day > 9 ? day.toString() : '0' + day.toString()
  if (format === 'short') {
    return now.getUTCFullYear().toString() + month + day
  } else {
    const hours =
      now.getUTCHours() > 9 ? now.getUTCHours() : '0' + now.getUTCHours()
    const minutes =
      now.getUTCMinutes() > 9 ? now.getUTCMinutes() : '0' + now.getUTCMinutes()
    const seconds =
      now.getUTCSeconds() > 9 ? now.getUTCSeconds() : '0' + now.getUTCSeconds()
    return (
      now.getUTCFullYear().toString() +
      month +
      day +
      'T' +
      hours +
      minutes +
      seconds +
      'Z'
    )
  }
}

function getAuthHeader(
  timeStamp,
  host,
  path,
  query,
  headers,
  method,
  region,
  service,
  accessKeyId,
  secretAccessKey,
  payload
) {
  const authHeader =
    'AWS4-HMAC-SHA256 ' +
    'Credential=' +
    accessKeyId +
    '/' +
    getFormattedDate(timeStamp, 'short') +
    '/' +
    region +
    '/' +
    service +
    '/aws4_request, ' +
    'SignedHeaders=' +
    (headers['Content-Type'] || headers['content-type']
      ? 'content-type:'
      : '') +
    'host;x-amz-date, ' +
    'Signature=' +
    getAwsSignature(
      timeStamp,
      host,
      path,
      query,
      headers,
      method,
      region,
      service,
      accessKeyId,
      secretAccessKey,
      payload
    )
  return authHeader
}

export const sign = function(opts, config) {
  const url = new URL(opts.url)
  const query =
    url.search.length && url.search[0] === '?'
      ? url.search.slice(1)
      : url.search
  const now = new Date()
  opts.headers = opts.headers || {}
  opts.headers.Authorization = getAuthHeader(
    now,
    url.hostname,
    url.pathname,
    query,
    opts.headers,
    opts.method,
    config.region,
    config.service,
    config.accessKeyId,
    config.secretAccessKey,
    opts.data
  )
  opts.headers['X-Amz-Date'] = getFormattedDate(now, 'long')
}
