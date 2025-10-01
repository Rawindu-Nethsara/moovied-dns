// Google Drive Proxy - Enhanced Vercel Edge Function
export const config = {
  runtime: 'edge',
}

export default async function handler(request) {
  // Handle CORS preflight
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
      usage: 'https://your-domain.vercel.app/api/download?id=FILE_ID'
    }), {
      status: 400,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })
  }

  try {
    // Strategy 1: Try direct download endpoints with various methods
    const directMethods = [
      {
        url: `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Referer': 'https://drive.google.com/',
          'Origin': 'https://drive.google.com',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'same-site'
        }
      },
      {
        url: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
          'Accept': '*/*',
          'From': 'googlebot@google.com'
        }
      },
      {
        url: `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
        headers: {
          'User-Agent': 'curl/8.0.1',
          'Accept': 'application/octet-stream'
        }
      },
      {
        url: `https://docs.google.com/uc?export=download&id=${fileId}&confirm=t`,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': '*/*'
        }
      },
      {
        url: `https://drive.google.com/uc?export=download&id=${fileId}`,
        headers: {
          'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
          'Accept': '*/*'
        }
      }
    ]

    // Try all direct methods
    for (const method of directMethods) {
      try {
        const rangeHeader = request.headers.get('Range')
        if (rangeHeader) {
          method.headers['Range'] = rangeHeader
        }

        const response = await fetch(method.url, {
          headers: method.headers,
          redirect: 'follow'
        })

        if (await isValidFileResponse(response)) {
          return createProxyResponse(response)
        }
      } catch (e) {
        continue
      }
    }

    // Strategy 2: Try to extract download link from confirmation page
    const confirmResult = await tryConfirmationPage(fileId, request)
    if (confirmResult.success) {
      return confirmResult.response
    }

    // Strategy 3: Try alternative endpoints with UUID
    const uuid = generateUUID()
    const alternativeUrls = [
      `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t&uuid=${uuid}`,
      `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t&uuid=${uuid}`,
      `https://docs.google.com/uc?id=${fileId}&export=download`
    ]

    for (const url of alternativeUrls) {
      try {
        const response = await fetch(url, {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
          }
        })

        if (await isValidFileResponse(response)) {
          return createProxyResponse(response)
        }
      } catch (e) {
        continue
      }
    }

    // All methods failed
    return new Response(JSON.stringify({ 
      error: 'Download failed',
      message: 'Unable to download file after trying all methods. Please verify: 1) File exists, 2) Sharing is set to "Anyone with the link can view", 3) File is not restricted by organization policies.',
      fileId: fileId,
      hint: 'Go to Google Drive → Right-click file → Share → Change to "Anyone with the link" → Viewer'
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
      fileId: fileId
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })
  }
}

// Check if response is a valid file (not an error page)
async function isValidFileResponse(response) {
  if (!response.ok && response.status !== 206) {
    return false
  }

  const contentType = response.headers.get('content-type') || ''
  const contentLength = parseInt(response.headers.get('content-length') || '0')

  // If it's HTML, check if it's a small error page
  if (contentType.includes('text/html')) {
    if (contentLength > 0 && contentLength < 100000) {
      // Small HTML file - likely error page
      const text = await response.clone().text()
      if (text.includes('Google Drive') && (text.includes('quota') || text.includes('error') || text.includes('access'))) {
        return false
      }
      // Could be actual small HTML file
      if (contentLength < 5000) {
        return false
      }
    }
  }

  // Valid if: has content-length, or is streaming, or is not HTML
  return contentLength > 0 || !contentType.includes('text/html')
}

// Try to extract download link from Google Drive confirmation page
async function tryConfirmationPage(fileId, request) {
  try {
    const confirmUrl = `https://drive.google.com/uc?export=download&id=${fileId}`
    
    const response = await fetch(confirmUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://drive.google.com/'
      }
    })

    if (!response.ok) {
      return { success: false }
    }

    const html = await response.text()

    // Multiple regex patterns to find download URL
    const patterns = [
      // Pattern 1: Direct download link with uuid
      /href="(https:\/\/drive\.usercontent\.google\.com\/download\?[^"]+)"/i,
      // Pattern 2: Export download with confirm
      /href="(https:\/\/[^"]*uc\?export=download[^"]*confirm=[^"]*uuid=[^"]*)"/i,
      // Pattern 3: JSON format
      /"downloadUrl"\s*:\s*"([^"]+)"/i,
      // Pattern 4: Form action
      /action="([^"]*uc\?export=download[^"]*)"/i,
      // Pattern 5: Relative URL
      /href="(\/uc\?export=download&[^"]+)"/i,
      // Pattern 6: Window location redirect
      /window\.location\s*=\s*['"](https?:\/\/[^'"]+)['"]?/i,
      // Pattern 7: Download attribute
      /download[^>]*href="([^"]+)"/i
    ]

    for (const pattern of patterns) {
      const match = html.match(pattern)
      if (match) {
        let downloadUrl = match[1]
          .replace(/&amp;/g, '&')
          .replace(/\\u003d/g, '=')
          .replace(/\\u0026/g, '&')
          .replace(/\\\//g, '/')
          .replace(/\\"/g, '"')

        // Make sure URL is absolute
        if (downloadUrl.startsWith('/')) {
          downloadUrl = 'https://drive.google.com' + downloadUrl
        }

        // Skip if it's just the same confirmation URL
        if (downloadUrl.includes('uc?export=download') && !downloadUrl.includes('confirm=') && !downloadUrl.includes('uuid=')) {
          continue
        }

        try {
          const downloadHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Referer': confirmUrl,
            'Origin': 'https://drive.google.com'
          }

          const rangeHeader = request.headers.get('Range')
          if (rangeHeader) {
            downloadHeaders['Range'] = rangeHeader
          }

          const finalResponse = await fetch(downloadUrl, {
            headers: downloadHeaders,
            redirect: 'follow'
          })

          if (await isValidFileResponse(finalResponse)) {
            return { 
              success: true, 
              response: createProxyResponse(finalResponse) 
            }
          }
        } catch (e) {
          continue
        }
      }
    }

    return { success: false }
  } catch (error) {
    return { success: false }
  }
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
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
    'last-modified',
    'content-encoding'
  ]

  headersToProxy.forEach(header => {
    const value = originalResponse.headers.get(header)
    if (value) headers.set(header, value)
  })

  // Add CORS headers
  headers.set('Access-Control-Allow-Origin', '*')
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition')

  // Set cache
  if (!headers.has('cache-control')) {
    headers.set('Cache-Control', 'public, max-age=3600')
  }

  return new Response(originalResponse.body, {
    status: originalResponse.status,
    headers: headers
  })
}
