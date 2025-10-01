// ULTIMATE Google Drive Proxy - 100GB+ Files, 408 Timeout Fixed, 24h Quota Bypass
// Handles: Large files, timeouts, quota limits, private/public files

export const config = {
  runtime: 'edge',
  maxDuration: 300, // 5 minutes max for Vercel Edge
}

const SERVICE_ACCOUNT = {
  "type": "service_account",
  "project_id": "composed-sensor-473512-a9",
  "private_key_id": "8b7ef24f54e4fa3766a846ec2b26b1a5941717ec",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA1/r02F69y/U1\njN9C5yasWLnxFgjtbPMfNQ9trcp06mmRLBQOLGv7q4LBkDbRI6fO2etfLYA1UQid\nG+4yMzPCyJjhl7+CqJzDd/D/agFvH6PhNXpHBCrof7LQFcNnFP6Yfky8TW65CPBJ\niErtNFvlhS7AyryWTYaUadbgtKXGXQDBJvN019ks2vQaLL0ZKEP/NxFbWSu4Oxzg\nvKKZ1x9hfpZYvSYeU9MgrgyCjbwCh36ZL012+FW1hwA2+56aFdHbk/he8cVkRC1v\nUoWLnayku3vAXL7IBsMR7CXde0traz0/YULBvTebeSDURuUZsyg0w4yOXvlmbSaJ\nAa21zQt/AgMBAAECggEAOI1d//2P0xMD5t9X/dOxqKsgZE308kOYDJfP3Xcwvxab\nPMJzYzCtvhEu+DqliLFvHZ8UgkXiqkAISaKOONSBImcXRljtBZES39PFrfFVWFQs\nB/hZ0oerWaFRO+qV8h3bB7dKI5KFnOe9J6M7bdKD/IwRCOKraVx00gMzy5POZZwP\nj/7nRZpgsjYVLdLW06xs1wkm+bR/qrb+JYloGFQ/ttjI9ctRV6u531JfsX5lhrW8\n6Z30t+YNxFIertf1zJoTlma4WpmFVA3Ya+wQAgKI/l6t9UT3/FrPBEkmLDsFFgjG\nnmxgwBi7YCWx2CeGdncymF8/h80ihxPY7KbxvalosQKBgQD1NZa4xMYLVhdJqsc2\niQ4pVMiPK0F28s0SC0yrqR8rDRqQXkhoN0Q1GScysdv8htoX9GwaJUIUP7yDESxt\nDRx58ssXrB+gOcu/8DDMTxoW+9dbtlH6kT/XaHslis6PegmmMj3dl1OiMN47yMTK\ncu/jE6gfxXDcrNLaoPxdXD/UFwKBgQDJVHcM8/QmQBAlFp4WcLrKqKWZvWLu82b4\nnjfMZjYHcVr7Rkiws9SuhOSLaiDCAzTU+6bPjZ2eLTzUONXU7Z0E1qbf6IrvxWUR\nNFG+YILaGZV97wQ1pOJXgCWQKYa21y6r9hgtY0vfmRQAa30B8VH3z8NXDx5Tp4yG\nAI7n4pZc2QKBgF54W+4pmWdKrsQp8IA5Q2R3DqHh92G9X3aBNfO4v5JVhRNzz4+f\nIz8Vxr1IOsnKpoGuIGveSNwGRjl0x1noQD1XZhljrfeL7Myw3AwKubF7K1hhIKpZ\nhXAXB8LJ/JTYXplSJ/WUVJtbGnOMAQ1CRNuGejJrXfUW/FFQzomlfc3XAoGAVceS\nLcenR8DV4CeB1cfUHlK6tAVYKL02K0mmNoV6EbO/cv4gLIGCZZUjly7xpBgfo3tR\nOG97L5DQsQ9CNEXFN/GJCi+XOs+c3zaueXG/btOluRFkdsK42VU1K/Y1eqO2M/hX\nlscO5cbgGcmyamh6Zx5zeR1s63Gg0ttcB/qn3AkCgYA+QlqwbqKeWwBQiIVfUcQU\npZZUAGkwk9m/kFJOLwo3UN7RkYcLFW4wm2xq52VYntbYiUzFqjam/ryavqZnPArM\ni7kFb1mya3BP0T0LxY/gFSWEx7pLNhkrmPmHC1jG+wehmxjF8hed/dkvcWjByf9o\nxqp+Ix0Rc5YR7R1XZImbNQ==\n-----END PRIVATE KEY-----\n",
  "client_email": "moovied-site@composed-sensor-473512-a9.iam.gserviceaccount.com"
}

// JWT for OAuth
async function createJWT(serviceAccount) {
  const header = { alg: 'RS256', typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/drive.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }

  const encodeBase64Url = (obj) => 
    btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  
  const encodedHeader = encodeBase64Url(header)
  const encodedPayload = encodeBase64Url(payload)
  const signatureInput = `${encodedHeader}.${encodedPayload}`
  
  const pemContents = serviceAccount.private_key
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '')
  
  const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0))
  
  const key = await crypto.subtle.importKey(
    'pkcs8', binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  )

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key,
    new TextEncoder().encode(signatureInput)
  )

  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

  return `${signatureInput}.${encodedSignature}`
}

async function getAccessToken() {
  const jwt = await createJWT(SERVICE_ACCOUNT)
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  })
  const data = await response.json()
  return data.access_token
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Range',
        'Access-Control-Max-Age': '86400'
      }
    })
  }

  const { searchParams } = new URL(request.url)
  const fileId = searchParams.get('id')

  if (!fileId) {
    return new Response(JSON.stringify({ 
      error: 'Missing file ID',
      usage: 'https://moovied-dns.vercel.app/api/download?id=FILE_ID'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  try {
    // PRIORITY 1: Ultra-fast quota bypass methods (works for 24h limit)
    const quotaBypassResult = await tryQuotaBypassAdvanced(fileId, request)
    if (quotaBypassResult.success) {
      return quotaBypassResult.response
    }

    // PRIORITY 2: Large file streaming methods (100GB+ support)
    const largeFileResult = await tryLargeFileStream(fileId, request)
    if (largeFileResult.success) {
      return largeFileResult.response
    }

    // PRIORITY 3: Confirmation page bypass (for virus scan warning)
    const confirmResult = await tryConfirmationBypass(fileId, request)
    if (confirmResult.success) {
      return confirmResult.response
    }

    // PRIORITY 4: Service account authenticated download
    try {
      const accessToken = await getAccessToken()
      const authResult = await tryAuthDownload(fileId, accessToken, request)
      if (authResult.success) {
        return authResult.response
      }
    } catch (e) {
      // Continue to next method
    }

    // PRIORITY 5: Public direct methods
    const publicResult = await tryPublicDirect(fileId, request)
    if (publicResult.success) {
      return publicResult.response
    }

    // All methods failed
    return new Response(JSON.stringify({ 
      error: 'Download failed - All methods exhausted',
      fileId: fileId,
      instructions: [
        '1. For public files: Share → "Anyone with the link" → Viewer',
        '2. For private files: Share with ' + SERVICE_ACCOUNT.client_email,
        '3. Check file exists at: https://drive.google.com/file/d/' + fileId
      ],
      serviceAccount: SERVICE_ACCOUNT.client_email
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'Server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }
}

// ADVANCED QUOTA BYPASS - Works for 24h download limit
async function tryQuotaBypassAdvanced(fileId, request) {
  const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
  })

  const randomIP = () => `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`

  const methods = [
    // Method 1: UUID bypass with spoofed IP
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t&uuid=${uuid()}`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'X-Forwarded-For': randomIP(),
        'X-Real-IP': randomIP(),
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
      }
    },
    // Method 2: Mobile user agent bypass
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t&uuid=${uuid()}`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
        'Accept': '*/*'
      }
    },
    // Method 3: Curl bypass with random session
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`,
      headers: {
        'User-Agent': 'curl/8.4.0',
        'Cookie': `download_warning_${fileId}=${uuid()}`
      }
    },
    // Method 4: Bot bypass
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Accept': '*/*'
      }
    },
    // Method 5: Alternative domain
    {
      url: `https://docs.google.com/uc?export=download&id=${fileId}&confirm=t`,
      headers: {
        'User-Agent': 'Wget/1.21.3',
        'Accept': '*/*'
      }
    }
  ]

  for (const method of methods) {
    try {
      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) method.headers['Range'] = rangeHeader

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 15000) // 15s timeout

      const response = await fetch(method.url, { 
        headers: method.headers,
        signal: controller.signal,
        redirect: 'follow'
      })
      clearTimeout(timeout)

      const contentType = response.headers.get('content-type') || ''
      const contentLength = parseInt(response.headers.get('content-length') || '0')
      
      // Valid file response
      if ((response.ok || response.status === 206)) {
        // Skip small HTML error pages
        if (contentType.includes('text/html') && contentLength < 100000) {
          continue
        }
        // Accept non-HTML or large files
        if (!contentType.includes('text/html') || contentLength > 100000) {
          return { success: true, response: createStreamResponse(response) }
        }
      }
    } catch (e) {
      continue
    }
  }
  return { success: false }
}

// LARGE FILE STREAMING - Handles 100GB+ files
async function tryLargeFileStream(fileId, request) {
  const streamUrls = [
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
    `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`,
    `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`
  ]

  for (const url of streamUrls) {
    try {
      const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'identity', // Disable compression for streaming
        'Connection': 'keep-alive'
      }
      
      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) headers['Range'] = rangeHeader

      // Extended timeout for large files
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 30000) // 30s

      const response = await fetch(url, { 
        headers,
        signal: controller.signal,
        redirect: 'follow'
      })
      clearTimeout(timeout)

      const contentType = response.headers.get('content-type') || ''
      
      if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
        return { success: true, response: createStreamResponse(response) }
      }
    } catch (e) {
      continue
    }
  }
  return { success: false }
}

// CONFIRMATION PAGE BYPASS - Skips "Google can't scan this file" page
async function tryConfirmationBypass(fileId, request) {
  try {
    const confirmUrl = `https://drive.google.com/uc?export=download&id=${fileId}`
    
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 12000)

    const response = await fetch(confirmUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml'
      },
      signal: controller.signal
    })
    clearTimeout(timeout)

    if (!response.ok) return { success: false }

    const html = await response.text()
    
    // Extract download URLs from confirmation page
    const patterns = [
      /href="(https:\/\/drive\.usercontent\.google\.com\/download\?[^"]+)"/i,
      /href="(https:\/\/[^"]*uc\?export=download[^"]*confirm=[^"]*uuid=[^"]*)"/i,
      /"downloadUrl"\s*:\s*"([^"]+)"/i,
      /action="([^"]*uc\?export=download[^"]*)"/i,
      /href="(\/uc\?export=download&[^"]+)"/i,
      /window\.location\.href\s*=\s*"([^"]+)"/i,
      /data-download-url="([^"]+)"/i
    ]

    for (const pattern of patterns) {
      const match = html.match(pattern)
      if (match) {
        let downloadUrl = match[1]
          .replace(/&amp;/g, '&')
          .replace(/\\u003d/g, '=')
          .replace(/\\u0026/g, '&')
          .replace(/\\\//g, '/')
          .replace(/&#x3d;/g, '=')

        if (downloadUrl.startsWith('/')) {
          downloadUrl = 'https://drive.google.com' + downloadUrl
        }

        try {
          const rangeHeader = request.headers.get('Range')
          const finalHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': confirmUrl,
            'Accept': '*/*'
          }
          if (rangeHeader) finalHeaders['Range'] = rangeHeader

          const finalController = new AbortController()
          const finalTimeout = setTimeout(() => finalController.abort(), 20000)

          const finalResponse = await fetch(downloadUrl, {
            headers: finalHeaders,
            signal: finalController.signal,
            redirect: 'follow'
          })
          clearTimeout(finalTimeout)

          const contentType = finalResponse.headers.get('content-type') || ''
          if ((finalResponse.ok || finalResponse.status === 206) && !contentType.includes('text/html')) {
            return { success: true, response: createStreamResponse(finalResponse) }
          }
        } catch (e) {
          continue
        }
      }
    }
  } catch (e) {
    return { success: false }
  }
  return { success: false }
}

// AUTHENTICATED DOWNLOAD - For private files
async function tryAuthDownload(fileId, accessToken, request) {
  const endpoints = [
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`
  ]

  for (const url of endpoints) {
    try {
      const headers = { 
        'Authorization': `Bearer ${accessToken}`,
        'Accept': '*/*',
        'Accept-Encoding': 'identity'
      }
      
      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) headers['Range'] = rangeHeader

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 20000)

      const response = await fetch(url, { 
        headers,
        signal: controller.signal 
      })
      clearTimeout(timeout)

      if (response.ok || response.status === 206) {
        return { success: true, response: createStreamResponse(response) }
      }
    } catch (e) {
      continue
    }
  }
  return { success: false }
}

// PUBLIC DIRECT - Simple public file download
async function tryPublicDirect(fileId, request) {
  const methods = [
    { url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download`, ua: 'curl/8.0.1' },
    { url: `https://docs.google.com/uc?export=download&id=${fileId}`, ua: 'Wget/1.21.3' },
    { url: `https://drive.google.com/uc?export=download&id=${fileId}`, ua: 'Mozilla/5.0' }
  ]

  for (const method of methods) {
    try {
      const headers = { 'User-Agent': method.ua, 'Accept': '*/*' }
      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) headers['Range'] = rangeHeader

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 10000)

      const response = await fetch(method.url, { 
        headers,
        signal: controller.signal 
      })
      clearTimeout(timeout)

      const contentType = response.headers.get('content-type') || ''
      if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
        return { success: true, response: createStreamResponse(response) }
      }
    } catch (e) {
      continue
    }
  }
  return { success: false }
}

// CREATE STREAMING RESPONSE - Optimized for large files
function createStreamResponse(originalResponse) {
  const headers = new Headers()
  
  const headersToProxy = [
    'content-type', 'content-length', 'content-disposition',
    'content-range', 'accept-ranges', 'cache-control',
    'etag', 'last-modified'
  ]

  headersToProxy.forEach(header => {
    const value = originalResponse.headers.get(header)
    if (value) headers.set(header, value)
  })

  // CORS headers
  headers.set('Access-Control-Allow-Origin', '*')
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition')

  // Streaming optimizations
  if (!headers.has('accept-ranges')) {
    headers.set('Accept-Ranges', 'bytes')
  }
  
  if (!headers.has('cache-control')) {
    headers.set('Cache-Control', 'public, max-age=31536000, immutable')
  }

  // Enable streaming for large files
  headers.set('X-Content-Type-Options', 'nosniff')

  return new Response(originalResponse.body, {
    status: originalResponse.status,
    headers: headers
  })
}
