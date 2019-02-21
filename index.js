import HmacSHA256 from 'crypto-js/hmac-sha256'
import Sha256 from 'crypto-js/sha256'

function getRequestHeaders(args) {
  const { headers, host, timeStamp } = args
  return Object.keys(headers)
    .map(header => `${header.toLowerCase()}:${headers[header]}`)
    .concat([
      `host:${host}`,
      `x-amz-date:${getFormattedDate(timeStamp, 'long')}`
    ])
    .join('\n')
}

function getSignedHeaders(headers) {
  return (
    Object.keys(headers)
      .join(';')
      .toLowerCase() +
    (Object.keys(headers).length ? ';' : '') +
    'host;x-amz-date'
  )
}

function getCanonicalRequest(args) {
  const { path, query, headers, method, payload } = args
  const canonicalRequest = [
    `${method.toUpperCase()}`,
    `${path}`,
    `${query}`,
    `${getRequestHeaders(args)}`,
    ``,
    `${getSignedHeaders(headers)}`,
    `${Sha256(JSON.stringify(payload)).toString()}`
  ].join('\n')
  return canonicalRequest
}

function getHashedCanonicalRequest(request) {
  return Sha256(request).toString()
}

function getStringToSign(args, hashedRequest) {
  const { timeStamp, region, service } = args
  const stringToSign = [
    `AWS4-HMAC-SHA256`,
    `${getFormattedDate(timeStamp, 'long')}`,
    `${getFormattedDate(timeStamp, 'short')}/${region}/${service}/aws4_request`,
    `${hashedRequest}`
  ].join('\n')
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

function getAwsSignature(args) {
  const { timeStamp, region, service, secretAccessKey } = args
  const canonicalRequest = getCanonicalRequest(args)
  const hashedRequest = getHashedCanonicalRequest(canonicalRequest)
  const stringToSign = getStringToSign(args, hashedRequest)
  const signingKey = getSigningKey(timeStamp, region, service, secretAccessKey)
  const signature = getSignature(stringToSign, signingKey)
  return signature
}

function getFormattedDate(timeStamp, format) {
  const month =
    timeStamp.getUTCMonth() + 1 > 9
      ? timeStamp.getUTCMonth() + 1
      : `0${timeStamp.getUTCMonth() + 1}`
  const day =
    timeStamp.getUTCDate() > 9
      ? timeStamp.getUTCDate()
      : `0${timeStamp.getUTCDate()}`
  if (format === 'short') {
    return `${timeStamp.getUTCFullYear()}${month}${day}`
  } else {
    const hours =
      timeStamp.getUTCHours() > 9
        ? timeStamp.getUTCHours()
        : `0${timeStamp.getUTCHours()}`
    const minutes =
      timeStamp.getUTCMinutes() > 9
        ? timeStamp.getUTCMinutes()
        : `0${timeStamp.getUTCMinutes()}`
    const seconds =
      timeStamp.getUTCSeconds() > 9
        ? timeStamp.getUTCSeconds()
        : `0${timeStamp.getUTCSeconds()}`
    return `${timeStamp.getUTCFullYear()}${month}${day}T${hours}${minutes}${seconds}Z`
  }
}

function getAuthHeader(args) {
  const { timeStamp, headers, region, service, accessKeyId } = args

  const formattedTimeStamp = getFormattedDate(timeStamp, 'short')
  const signedHeaders = getSignedHeaders(headers)
  const signature = getAwsSignature(args)
  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${formattedTimeStamp}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}`
  return authHeader
}

export const sign = function(opts, config) {
  const { url, method, data } = opts
  const { region, service, accessKeyId, secretAccessKey } = config
  const urlObject = new URL(url)
  const { search, hostname, pathname } = urlObject
  const query = search.length && search[0] === '?' ? search.slice(1) : search
  const now = new Date()
  opts.headers = opts.headers || {}
  opts.headers.Authorization = getAuthHeader({
    timeStamp: now,
    host: hostname,
    path: pathname,
    query,
    headers: opts.headers,
    method,
    region,
    service,
    accessKeyId,
    secretAccessKey,
    payload: data
  })
  opts.headers['X-Amz-Date'] = getFormattedDate(now, 'long')
}
