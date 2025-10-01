// ULTIMATE Google Drive Proxy - Zero Bandwidth Usage
// Returns direct Google Drive URLs instead of proxying content

export const config = {
  runtime: 'edge',
}

const SERVICE_ACCOUNT = {
  "type": "service_account",
  "project_id": "composed-sensor-473512-a9",
  "private_key_id": "8b7ef24f54e4fa3766a846ec2b26b1a5941717ec",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA1/r02F69y/U1\njN9C5yasWLnxFgjtbPMfNQ9trcp06mmRLBQOLGv7q4LBkDbRI6fO2etfLYA1UQid\nG+4yMzPCyJjhl7+CqJzDd/D/agFvH6PhNXpHBCrof7LQFcNnFP6Yfky8TW65CPBJ\niErtNFvlhS7AyryWTYaUadbgtKXGXQDBJvN019ks2vQaLL0ZKEP/NxFbWSu4Oxzg\nvKKZ1x9hfpZYvSYeU9MgrgyCjbwCh36ZL012+FW1hwA2+56aFdHbk/he8cVkRC1v\nUoWLnayku3vAXL7IBsMR7CXde0traz0/YULBvTebeSDURuUZsyg0w4yOXvlmbSaJ\nAa21zQt/AgMBAAECggEAOI1d//2P0xMD5t9X/dOxqKsgZE308kOYDJfP3Xcwvxab\nPMJzYzCtvhEu+DqliLFvHZ8UgkXiqkAISaKOONSBImcXRljtBZES39PFrfFVWFQs\nB/hZ0oerWaFRO+qV8h3bB7dKI5KFnOe9J6M7bdKD/IwRCOKraVx00gMzy5POZZwP\nj/7nRZpgsjYVLdLW06xs1wkm+bR/qrb+JYloGFQ/ttjI9ctRV6u531JfsX5lhrW8\n6Z30t+YNxFIertf1zJoTlma4WpmFVA3Ya+wQAgKI/l6t9UT3/FrPBEkmLDsFFgjG\nnmxgwBi7YCWx2CeGdncymF8/h80ihxPY7KbxvalosQKBgQD1NZa4xMYLVhdJqsc2\niQ4pVMiPK0F28s0SC0yrqR8rDRqQXkhoN0Q1GScysdv8htoX9GwaJUIUP7yDESxt\nDRx58ssXrB+gOcu/8DDMTxoW+9dbtlH6kT/XaHslis6PegmmMj3dl1OiMN47yMTK\ncu/jE6gfxXDcrNLaoPxdXD/UFwKBgQDJVHcM8/QmQBAlFp4WcLrKqKWZvWLu82b4\nnjfMZjYHcVr7Rkiws9SuhOSLaiDCAzTU+6bPjZ2eLTzUONXU7Z0E1qbf6IrvxWUR\nNFG+YILaGZV97wQ1pOJXgCWQKYa21y6r9hgtY0vfmRQAa30B8VH3z8NXDx5Tp4yG\nAI7n4pZc2QKBgF54W+4pmWdKrsQp8IA5Q2R3DqHh92G9X3aBNfO4v5JVhRNzz4+f\nIz8Vxr1IOsnKpoGuIGveSNwGRjl0x1noQD1XZhljrfeL7Myw3AwKubF7K1hhIKpZ\nhXAXB8LJ/JTYXplSJ/WUVJtbGnOMAQ1CRNuGejJrXfUW/FFQzomlfc3XAoGAVceS\nLcenR8DV4CeB1cfUHlK6tAVYKL02K0mmNoV6EbO/cv4gLIGCZZUjly7xpBgfo3tR\nOG97L5DQsQ9CNEXFN/GJCi+XOs+c3zaueXG/btOluRFkdsK42VU1K/Y1eqO2M/hX\nlscO5cbgGcmyamh6Zx5zeR1s63Gg0ttcB/qn3AkCgYA+QlqwbqKeWwBQiIVfUcQU\npZZUAGkwk9m/kFJOLwo3UN7RkYcLFW4wm2xq52VYntbYiUzFqjam/ryavqZnPArM\ni7kFb1mya3BP0T0LxY/gFSWEx7pLNhkrmPmHC1jG+wehmxjF8hed/dkvcWjByf9o\nxqp+Ix0Rc5YR7R1XZImbNQ==\n-----END PRIVATE KEY-----\n",
  "client_email": "moovied-site@composed-sensor-473512-a9.iam.gserviceaccount.com"
}

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
    'pkcs8',
    binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
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
  const mode = searchParams.get('mode') || 'redirect' // 'redirect' or 'proxy'

  if (!fileId) {
    return new Response(JSON.stringify({ 
      error: 'Missing file ID',
      usage: 'Redirect mode (zero bandwidth): ?id=FILE_ID&mode=redirect\nProxy mode (uses bandwidth): ?id=FILE_ID&mode=proxy'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  try {
    // MODE 1: REDIRECT (Zero Bandwidth - Recommended for large files)
    if (mode === 'redirect') {
      // Try to get direct download URL
      const directUrl = await getDirectDownloadUrl(fileId)
      if (directUrl) {
        return Response.redirect(directUrl, 302)
      }
      
      // Fallback: redirect to Google Drive viewer
      return Response.redirect(`https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`, 302)
    }

    // MODE 2: PROXY (Uses Bandwidth - For small files or when redirect fails)
    if (mode === 'proxy') {
      // Try public methods first
      const publicResult = await tryPublicMethods(fileId, request)
      if (publicResult.success) {
        return publicResult.response
      }

      // Try with authentication
      const accessToken = await getAccessToken()
      const authResult = await tryAuthDownload(fileId, accessToken, request)
      if (authResult.success) {
        return authResult.response
      }

      return new Response(JSON.stringify({ 
        error: 'Download failed',
        message: 'Unable to proxy file. Try redirect mode instead: ?id=' + fileId + '&mode=redirect'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      })
    }

    // DEFAULT: Auto-detect (redirect for large files, proxy for small)
    const fileInfo = await getFileInfo(fileId)
    if (fileInfo && fileInfo.size > 50 * 1024 * 1024) { // > 50MB
      const directUrl = await getDirectDownloadUrl(fileId)
      if (directUrl) {
        return Response.redirect(directUrl, 302)
      }
    }

    // Small file - proxy it
    const publicResult = await tryPublicMethods(fileId, request)
    if (publicResult.success) {
      return publicResult.response
    }

    const accessToken = await getAccessToken()
    const authResult = await tryAuthDownload(fileId, accessToken, request)
    if (authResult.success) {
      return authResult.response
    }

    return new Response(JSON.stringify({ 
      error: 'Download failed',
      hint: 'Try: ?id=' + fileId + '&mode=redirect for large files'
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

// Get file info (size, name, etc.)
async function getFileInfo(fileId) {
  try {
    const accessToken = await getAccessToken()
    const response = await fetch(
      `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType&supportsAllDrives=true`,
      { headers: { 'Authorization': `Bearer ${accessToken}` } }
    )
    if (response.ok) {
      return await response.json()
    }
  } catch (e) {
    return null
  }
  return null
}

// Get direct download URL (bypasses quota in many cases)
async function getDirectDownloadUrl(fileId) {
  const urls = [
    `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
    `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`
  ]
  
  for (const url of urls) {
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        redirect: 'manual'
      })
      
      // If it redirects or returns OK, this URL works
      if (response.status === 302 || response.status === 200) {
        return url
      }
    } catch (e) {
      continue
    }
  }
  return null
}

async function tryAuthDownload(fileId, accessToken, request) {
  try {
    const url = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`
    const headers = { 'Authorization': `Bearer ${accessToken}`, 'Accept': '*/*' }
    
    const rangeHeader = request.headers.get('Range')
    if (rangeHeader) headers['Range'] = rangeHeader

    const response = await fetch(url, { headers })

    if (response.ok || response.status === 206) {
      return { success: true, response: createProxyResponse(response) }
    }
  } catch (e) {
    return { success: false }
  }
  return { success: false }
}

async function tryPublicMethods(fileId, request) {
  const methods = [
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    },
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
      ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    }
  ]

  for (const method of methods) {
    try {
      const headers = { 'User-Agent': method.ua, 'Accept': '*/*' }
      const rangeHeader = request.headers.get('Range')
      if (rangeHeader) headers['Range'] = rangeHeader

      const response = await fetch(method.url, { headers, redirect: 'follow' })
      const contentType = response.headers.get('content-type') || ''
      
      if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
        return { success: true, response: createProxyResponse(response) }
      }
    } catch (e) {
      continue
    }
  }
  return { success: false }
}

function createProxyResponse(originalResponse) {
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
