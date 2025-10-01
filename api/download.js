// Vercel Edge Function - 24h Quota Bypass with Multiple Mirrors
// Automatically rotates between multiple Google Drive accounts
// If one gets 403, tries next mirror

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

// FILE MIRRORS CONFIGURATION
// Add multiple copies of the same file from different Google accounts
const FILE_MIRRORS = {
  // Example: "movie_name": ["fileID1", "fileID2", "fileID3"]
  // Add your mirrors here:
  
  "example_movie": [
    "1sGquZwp92VuDLLGThzkHQ4JyNVitDFaU",  // Mirror 1 (Account 1)
    "1abc123xyz456def789ghi012jkl345mn",  // Mirror 2 (Account 2)
    "1qwe098rty765uio432plk109mnb876vc"   // Mirror 3 (Account 3)
  ]
  
  // Add more movies:
  // "movie2": ["id1", "id2", "id3"],
  // "movie3": ["id1", "id2", "id3"],
}

const quotaCache = new Map() // Track which files are in quota

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

// Check if file has quota issues (403)
async function checkFileQuota(fileId, accessToken) {
  try {
    const response = await fetch(
      `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
      {
        method: 'HEAD',
        headers: { 'Authorization': `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(5000)
      }
    )
    
    // 403 = quota exceeded
    if (response.status === 403) {
      return { hasQuota: true, status: 403 }
    }
    
    // 200/206 = OK
    if (response.ok) {
      return { hasQuota: false, status: response.status }
    }
    
    // Other errors
    return { hasQuota: true, status: response.status }
    
  } catch (e) {
    return { hasQuota: true, status: 'timeout' }
  }
}

// Find working mirror from list
async function findWorkingMirror(mirrors, accessToken) {
  const results = []
  
  for (let i = 0; i < mirrors.length; i++) {
    const fileId = mirrors[i]
    
    // Check cache first
    const cached = quotaCache.get(fileId)
    if (cached && cached.hasQuota && (Date.now() - cached.timestamp) < 3600000) {
      console.log(`[SKIP] ${fileId} - Cached as quota exceeded`)
      results.push({ fileId, hasQuota: true, source: 'cache' })
      continue
    }
    
    // Test file
    const check = await checkFileQuota(fileId, accessToken)
    console.log(`[TEST] Mirror ${i + 1}/${mirrors.length} - ${fileId} - Status: ${check.status}`)
    
    // Cache result
    quotaCache.set(fileId, {
      hasQuota: check.hasQuota,
      timestamp: Date.now()
    })
    
    results.push({ fileId, ...check })
    
    // Found working mirror!
    if (!check.hasQuota) {
      return { success: true, fileId, mirrorIndex: i, results }
    }
  }
  
  // All mirrors failed
  return { success: false, results }
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
  const movieKey = searchParams.get('movie') // Use movie key for mirrors

  if (!fileId && !movieKey) {
    return new Response(JSON.stringify({ 
      error: 'Missing parameter',
      usage: 'Use ?id=FILE_ID or ?movie=MOVIE_KEY (for auto-rotation)',
      example: '?movie=example_movie'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  try {
    const accessToken = await getAccessToken()
    let targetFileId = fileId
    let mirrorInfo = null

    // If movie key provided, use mirror rotation
    if (movieKey && FILE_MIRRORS[movieKey]) {
      console.log(`[MIRROR MODE] ${movieKey} - Finding working mirror...`)
      
      const mirrors = FILE_MIRRORS[movieKey]
      const result = await findWorkingMirror(mirrors, accessToken)
      
      if (!result.success) {
        return new Response(JSON.stringify({ 
          error: 'All mirrors exceeded quota',
          movieKey: movieKey,
          totalMirrors: mirrors.length,
          results: result.results,
          message: 'All copies of this file are currently quota-limited. Try again in 24 hours or add more mirrors.',
          hint: 'Create more copies on different Google accounts'
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        })
      }
      
      targetFileId = result.fileId
      mirrorInfo = {
        movieKey: movieKey,
        mirrorIndex: result.mirrorIndex + 1,
        totalMirrors: mirrors.length,
        testedMirrors: result.results.length
      }
      
      console.log(`[SUCCESS] Using mirror ${result.mirrorIndex + 1}/${mirrors.length} - ${targetFileId}`)
    }

    // Get file metadata
    const metaResponse = await fetch(
      `https://www.googleapis.com/drive/v3/files/${targetFileId}?fields=name,size,mimeType`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    )

    if (!metaResponse.ok) {
      return new Response(JSON.stringify({ 
        error: 'File not found or not accessible',
        fileId: targetFileId,
        hint: 'Share the file with: ' + SERVICE_ACCOUNT.client_email,
        note: 'Give "Viewer" permission'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      })
    }

    const metadata = await metaResponse.json()
    const fileName = metadata.name || 'download'
    const fileSize = metadata.size || '0'

    // Download file
    const downloadResponse = await fetch(
      `https://www.googleapis.com/drive/v3/files/${targetFileId}?alt=media&supportsAllDrives=true`,
      {
        headers: { 
          'Authorization': `Bearer ${accessToken}`,
          'Range': request.headers.get('Range') || ''
        }
      }
    )

    if (!downloadResponse.ok) {
      // 403 = Quota exceeded
      if (downloadResponse.status === 403) {
        // Mark this mirror as quota exceeded
        quotaCache.set(targetFileId, {
          hasQuota: true,
          timestamp: Date.now()
        })
        
        return new Response(JSON.stringify({ 
          error: 'Download quota exceeded',
          fileId: targetFileId,
          message: 'This file has exceeded its 24-hour download quota',
          hint: mirrorInfo ? 'Trying next mirror...' : 'Use ?movie=KEY for auto-rotation',
          mirrorInfo: mirrorInfo
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        })
      }
      
      throw new Error(`Download failed: ${downloadResponse.status}`)
    }

    // Success - stream file
    const headers = {
      'Content-Type': downloadResponse.headers.get('Content-Type') || 'application/octet-stream',
      'Content-Length': downloadResponse.headers.get('Content-Length') || fileSize,
      'Content-Disposition': `attachment; filename="${fileName}"`,
      'Accept-Ranges': 'bytes',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
      'X-File-Size': fileSize,
      'X-File-Name': fileName
    }

    // Add mirror info to headers
    if (mirrorInfo) {
      headers['X-Mirror-Used'] = `${mirrorInfo.mirrorIndex}/${mirrorInfo.totalMirrors}`
      headers['X-Movie-Key'] = mirrorInfo.movieKey
    }

    return new Response(downloadResponse.body, {
      status: downloadResponse.status,
      headers: headers
    })

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'Server error',
      message: error.message,
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }
}
