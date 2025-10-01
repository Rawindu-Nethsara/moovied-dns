// Google Drive Download - Quota Bypass + Direct Download
// Handles: 24h quota limits, unlimited downloads, large files (10GB+)
// Strategy: Multiple endpoints, user-agent rotation, confirmation bypass

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

// Generate unique identifiers for quota bypass
const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
  const r = Math.random() * 16 | 0
  return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
})

const randomIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400'
      }
    })
  }

  const { searchParams } = new URL(request.url)
  const fileId = searchParams.get('id')
  const action = searchParams.get('action') // 'url' or 'download'

  if (!fileId) {
    return new Response(JSON.stringify({ 
      error: 'Missing file ID',
      usage: 'Add ?id=FILE_ID&action=url or ?id=FILE_ID&action=download'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  try {
    const attempts = []

    // STRATEGY 1: UUID + Confirm bypass (best for quota limits)
    const uuidUrls = await getQuotaBypassUrls(fileId)
    for (const url of uuidUrls) {
      const result = await testUrl(url.url, url.headers)
      if (result.success) {
        attempts.push({ method: 'uuid_bypass', success: true })
        if (action === 'download') {
          return Response.redirect(url.url, 302)
        }
        return jsonResponse({
          success: true,
          downloadUrl: url.url,
          method: 'quota_bypass',
          fileId: fileId
        })
      }
      attempts.push({ method: 'uuid_bypass', success: false })
    }

    // STRATEGY 2: Confirmation page extraction
    const confirmUrl = await extractConfirmationUrl(fileId)
    if (confirmUrl) {
      attempts.push({ method: 'confirmation_page', success: true })
      if (action === 'download') {
        return Response.redirect(confirmUrl, 302)
      }
      return jsonResponse({
        success: true,
        downloadUrl: confirmUrl,
        method: 'confirmation_extraction',
        fileId: fileId
      })
    }
    attempts.push({ method: 'confirmation_page', success: false })

    // STRATEGY 3: Public direct URLs
    const publicUrl = await getPublicDownloadUrl(fileId)
    if (publicUrl) {
      attempts.push({ method: 'public_url', success: true })
      if (action === 'download') {
        return Response.redirect(publicUrl, 302)
      }
      return jsonResponse({
        success: true,
        downloadUrl: publicUrl,
        method: 'public_direct',
        fileId: fileId
      })
    }
    attempts.push({ method: 'public_url', success: false })

    // STRATEGY 4: Authenticated download (service account)
    try {
      const accessToken = await getAccessToken()
      const authUrl = await getAuthenticatedDownloadUrl(fileId, accessToken)
      
      if (authUrl) {
        attempts.push({ method: 'authenticated', success: true })
        if (action === 'download') {
          return Response.redirect(authUrl, 302)
        }
        return jsonResponse({
          success: true,
          downloadUrl: authUrl,
          method: 'service_account',
          fileId: fileId,
          note: 'Token expires in 1 hour'
        })
      }
      attempts.push({ method: 'authenticated', success: false })
    } catch (e) {
      attempts.push({ method: 'authenticated', success: false, error: e.message })
    }

    // All methods failed
    return jsonResponse({ 
      error: 'All download methods failed',
      fileId: fileId,
      attempts: attempts,
      instructions: [
        '1. Make file public: Share → Anyone with the link → Viewer',
        '2. OR share with: ' + SERVICE_ACCOUNT.client_email,
        '3. Check if file exists: https://drive.google.com/file/d/' + fileId + '/view'
      ]
    }, 403)

  } catch (error) {
    return jsonResponse({ 
      error: 'Server error',
      message: error.message
    }, 500)
  }
}

// QUOTA BYPASS: Generate URLs with UUID + various user agents
async function getQuotaBypassUrls(fileId) {
  const uniqueId = uuid()
  
  return [
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t&uuid=${uniqueId}`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'X-Forwarded-For': randomIP()
      }
    },
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t&uuid=${uniqueId}`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
        'X-Forwarded-For': randomIP()
      }
    },
    {
      url: `https://docs.google.com/uc?id=${fileId}&export=download&confirm=t&uuid=${uniqueId}`,
      headers: {
        'User-Agent': 'curl/8.4.0',
        'X-Forwarded-For': randomIP()
      }
    },
    {
      url: `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&key=AIzaSyC1eQ1xj69IdTMeii5r7brs3R90ek85noj`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 13)',
        'X-Forwarded-For': randomIP()
      }
    }
  ]
}

// Extract download URL from confirmation page (for large files)
async function extractConfirmationUrl(fileId) {
  try {
    const confirmUrl = `https://drive.google.com/uc?export=download&id=${fileId}`
    
    const response = await fetch(confirmUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html',
        'X-Forwarded-For': randomIP()
      },
      signal: AbortSignal.timeout(6000)
    })

    if (!response.ok) return null

    const html = await response.text()
    
    // Multiple patterns to extract download URL
    const patterns = [
      /href="(https:\/\/drive\.usercontent\.google\.com\/download\?[^"]+)"/i,
      /href="(https:\/\/[^"]*uc\?export=download[^"]*confirm=[^"]*uuid=[^"]*)"/i,
      /"downloadUrl"\s*:\s*"([^"]+)"/i,
      /action="([^"]*uc\?export=download[^"]*)"/i,
      /href="(\/uc\?export=download&[^"]+)"/i,
      /<a[^>]*id="uc-download-link"[^>]*href="([^"]+)"/i
    ]

    for (const pattern of patterns) {
      const match = html.match(pattern)
      if (match) {
        let downloadUrl = match[1]
          .replace(/&amp;/g, '&')
          .replace(/\\u003d/g, '=')
          .replace(/\\u0026/g, '&')
          .replace(/\\\//g, '/')

        if (downloadUrl.startsWith('/')) {
          downloadUrl = 'https://drive.google.com' + downloadUrl
        }

        // Verify the URL works
        const testResult = await testUrl(downloadUrl, {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          'Referer': confirmUrl
        })

        if (testResult.success) {
          return downloadUrl
        }
      }
    }
  } catch (e) {
    return null
  }
  return null
}

// Generate standard public download URL
async function getPublicDownloadUrl(fileId) {
  const methods = [
    {
      url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
      ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    },
    {
      url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
      ua: 'Wget/1.21.4'
    }
  ]

  for (const method of methods) {
    const result = await testUrl(method.url, { 'User-Agent': method.ua })
    if (result.success) {
      return method.url
    }
  }

  return null
}

// Generate authenticated download URL (for private files)
async function getAuthenticatedDownloadUrl(fileId, accessToken) {
  const urls = [
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`
  ]
  
  for (const baseUrl of urls) {
    const result = await testUrl(baseUrl, {
      'Authorization': `Bearer ${accessToken}`
    })
    
    if (result.success) {
      return `${baseUrl}&access_token=${accessToken}`
    }
  }

  return null
}

// Test if URL is valid (returns file, not error page)
async function testUrl(url, headers = {}) {
  try {
    const response = await fetch(url, { 
      method: 'HEAD',
      headers: headers,
      signal: AbortSignal.timeout(4000)
    })
    
    const contentType = response.headers.get('content-type') || ''
    const contentLength = parseInt(response.headers.get('content-length') || '0')
    
    // Valid if: OK status AND (not HTML OR large HTML file)
    if (response.ok) {
      if (!contentType.includes('text/html')) {
        return { success: true }
      }
      if (contentLength > 50000) {
        return { success: true }
      }
    }
    
    return { success: false }
  } catch (e) {
    return { success: false }
  }
}

// Helper to create JSON responses
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: { 
      'Content-Type': 'application/json', 
      'Access-Control-Allow-Origin': '*' 
    }
  })
}
