import HmacSHA256 from 'crypto-js/hmac-sha256'
import Sha256 from 'crypto-js/sha256'

const getRequestHeaders = args => {
  const { headers, host, timeStamp } = args
  return Object.keys(headers)
    .map(header => `${header.toLowerCase()}:${headers[header]}`)
    .concat([
      `host:${host}`,
      `x-amz-date:${getFormattedDate(timeStamp, 'long')}`
    ])
    .join('\n')
}

const getSignedHeaders = headers => {
  const headerNames = Object.keys(headers).concat(['host', 'x-amz-date'])
  return headerNames.join(';').toLowerCase()
}

const getCanonicalRequest = args => {
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

const getStringToSign = (args, hashedRequest) => {
  const { timeStamp, region, service } = args
  const stringToSign = [
    `AWS4-HMAC-SHA256`,
    `${getFormattedDate(timeStamp, 'long')}`,
    `${getFormattedDate(timeStamp, 'short')}/${region}/${service}/aws4_request`,
    `${hashedRequest}`
  ].join('\n')
  return stringToSign
}

const getSigningKey = args => {
  const { timeStamp, region, service, secretAccessKey } = args
  const dateStamp = getFormattedDate(timeStamp, 'short')
  const kDate = HmacSHA256(dateStamp, 'AWS4' + secretAccessKey)
  const kRegion = HmacSHA256(region, kDate)
  const kService = HmacSHA256(service, kRegion)
  const kSigning = HmacSHA256('aws4_request', kService)
  return kSigning
}

function getSignature(stringToSign, signingKey) {
  return HmacSHA256(stringToSign, signingKey).toString()
}

const getAwsSignature = args => {
  const canonicalRequest = getCanonicalRequest(args)
  const hashedRequest = getHashedCanonicalRequest(canonicalRequest)
  const stringToSign = getStringToSign(args, hashedRequest)
  const signingKey = getSigningKey(args)
  const signature = getSignature(stringToSign, signingKey)
  return signature
}

const getFormattedDate = (timeStamp, format) => {
  const utcMonth = timeStamp.getUTCMonth() + 1
  const utcDay = timeStamp.getUTCDate()
  const month = utcMonth > 9 ? utcMonth : `0${utcMonth}`
  const day = utcDay > 9 ? utcDay : `0${utcDay}`
  if (format === 'short') {
    return `${timeStamp.getUTCFullYear()}${month}${day}`
  } else {
    const utcHours = timeStamp.getUTCHours()
    const utcMinutes = timeStamp.getUTCMinutes()
    const utcSeconds = timeStamp.getUTCSeconds()
    const hours = utcHours > 9 ? utcHours : `0${utcHours}`
    const minutes = utcMinutes > 9 ? utcMinutes : `0${utcMinutes}`
    const seconds = utcSeconds > 9 ? utcSeconds : `0${utcSeconds}`
    return `${timeStamp.getUTCFullYear()}${month}${day}T${hours}${minutes}${seconds}Z`
  }
}

const getAuthHeader = args => {
  const { timeStamp, headers, region, service, accessKeyId } = args
  const formattedTimeStamp = getFormattedDate(timeStamp, 'short')
  const signedHeaders = getSignedHeaders(headers)
  const signature = getAwsSignature(args)
  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${formattedTimeStamp}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}`
  return authHeader
}

export const sign = (opts, config) => {
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
