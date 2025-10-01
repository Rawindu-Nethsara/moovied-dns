// Google Drive Proxy - Private Files Support with Service Account
// Handles: Private files, 403 quota, 408 timeout

export const config = {
  runtime: 'edge',
}

// Base64 decode helper for edge runtime
function base64Decode(str) {
  return atob(str)
}

// Create JWT for Google OAuth
async function createJWT(serviceAccount, scopes) {
  const header = {
    alg: 'RS256',
    typ: 'JWT'
  }

  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: serviceAccount.client_email,
    scope: scopes.join(' '),
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }

  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  
  const signatureInput = `${encodedHeader}.${encodedPayload}`
  
  // Import private key
  const pemHeader = '-----BEGIN PRIVATE KEY-----'
  const pemFooter = '-----END PRIVATE KEY-----'
  const pemContents = serviceAccount.private_key.substring(
    pemHeader.length,
    serviceAccount.private_key.length - pemFooter.length - 1
  ).replace(/\s/g, '')
  
  const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0))
  
  const key = await crypto.subtle.importKey(
    'pkcs8',
    binaryKey,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signatureInput)
  )

  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')

  return `${signatureInput}.${encodedSignature}`
}

// Get access token from Google
async function getAccessToken(serviceAccount) {
  const jwt = await createJWT(serviceAccount, [
    'https://www.googleapis.com/auth/drive.readonly'
  ])

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  })

  const data = await response.json()
  return data.access_token
}

export default async function handler(request) {
  // Handle CORS
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
  const useAuth = searchParams.get('private') === 'true' // Add ?private=true for private files

  if (!fileId) {
    return new Response(JSON.stringify({ 
      error: 'Missing file ID',
      usage: 'Public: ?id=FILE_ID | Private: ?id=FILE_ID&private=true'
    }), {
      status: 400,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })
  }

  try {
    // Method 1: Try public download first (fast, no auth)
    if (!useAuth) {
      const publicResult = await tryPublicDownload(fileId, request)
      if (publicResult.success) {
        return publicResult.response
      }
    }

    // Method 2: Try with authentication (for private files)
    // You need to set this environment variable in Vercel
    const serviceAccountJson = process.env.GOOGLE_SERVICE_ACCOUNT
    
    if (serviceAccountJson) {
      const serviceAccount = JSON.parse(serviceAccountJson)
      const accessToken = await getAccessToken(serviceAccount)
      
      // Download with authentication
      const authResult = await downloadWithAuth(fileId, accessToken, request)
      if (authResult.success) {
        return authResult.response
      }
    }

    // Method 3: Fallback to aggressive public methods
    const aggressiveResult = await tryAggressiveMethods(fileId, request)
    if (aggressiveResult.success) {
      return aggressiveResult.response
    }

    // All methods failed
    return new Response(JSON.stringify({ 
      error: 'Download failed',
      message: serviceAccountJson 
        ? 'File not accessible. Make sure the file is shared with the service account email.'
        : 'File is private. Add ?private=true or share the file publicly.',
      fileId: fileId,
      hint: 'For private files: Share file with service account or add ?private=true'
    }), {
      status: 403,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'Server error',
      message: error.message,
      stack: error.stack
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })
  }
}

// Download with OAuth authentication
async function downloadWithAuth(fileId, accessToken, request) {
  try {
    const url = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`
    
    const headers = {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': '*/*'
    }

    const rangeHeader = request.headers.get('Range')
    if (rangeHeader) {
      headers['Range'] = rangeHeader
    }

    const response = await fetch(url, { headers })

    if (response.ok || response.status === 206) {
      return { 
        success: true, 
        response: createProxyResponse(response) 
      }
    }

    return { success: false }
  } catch (error) {
    return { success: false }
  }
}

// Try public download (no authentication)
async function tryPublicDownload(fileId, request) {
  const methods = [
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    },
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
      ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    },
    {
      url: `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
      ua: 'curl/8.0.1'
    }
  ]

  for (const method of methods) {
    try {
      const headers = {
        'User-Agent': method.ua,
        'Accept': '*/*'
      }

      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) {
        headers['Range'] = rangeHeader
      }

      // Abort after 5 seconds to prevent 408 timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000)

      const response = await fetch(method.url, {
        headers,
        signal: controller.signal,
        redirect: 'follow'
      })

      clearTimeout(timeoutId)

      const contentType = response.headers.get('content-type') || ''
      
      if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
        return { 
          success: true, 
          response: createProxyResponse(response) 
        }
      }
    } catch (error) {
      continue
    }
  }

  return { success: false }
}

// Aggressive methods for quota-exceeded files
async function tryAggressiveMethods(fileId, request) {
  const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
  })

  const methods = [
    `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t&uuid=${uuid()}`,
    `https://docs.google.com/uc?export=download&id=${fileId}&confirm=t`,
    `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t&uuid=${uuid()}`
  ]

  const userAgents = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'curl/7.88.0',
    'Wget/1.21.3'
  ]

  for (const url of methods) {
    for (const ua of userAgents) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), 5000)

        const response = await fetch(url, {
          headers: {
            'User-Agent': ua,
            'Accept': '*/*'
          },
          signal: controller.signal
        })

        clearTimeout(timeoutId)

        const contentType = response.headers.get('content-type') || ''
        if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
          return { 
            success: true, 
            response: createProxyResponse(response) 
          }
        }
      } catch (error) {
        continue
      }
    }
  }

  return { success: false }
}

function createProxyResponse(originalResponse) {
  const headers = new Headers()
  
  const headersToProxy = [
    'content-type',
    'content-length',
    'content-disposition',
    'content-range',
    'accept-ranges',
    'cache-control',
    'etag',
    'last-modified'
  ]

  headersToProxy.forEach(header => {
    const value = originalResponse.headers.get(header)
    if (value) headers.set(header, value)
  })

  headers.set('Access-Control-Allow-Origin', '*')
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges')

  if (!headers.has('cache-control')) {
    headers.set('Cache-Control', 'public, max-age=3600')
  }

  return new Response(originalResponse.body, {
    status: originalResponse.status,
    headers: headers
  })
}
