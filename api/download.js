// Google Drive Proxy - Vercel Edge Function
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
    // Try multiple Google Drive endpoints
    const endpoints = [
      `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
      `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
      `https://docs.google.com/uc?export=download&id=${fileId}&confirm=t`,
      `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`
    ]

    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
      'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
    ]

    // Try combinations of endpoints and user agents
    for (const endpoint of endpoints) {
      for (const ua of userAgents) {
        try {
          const headers = {
            'User-Agent': ua,
            'Accept': '*/*',
            'Referer': 'https://drive.google.com/',
            'Origin': 'https://drive.google.com'
          }

          // Forward Range header for video streaming
          const rangeHeader = request.headers.get('Range')
          if (rangeHeader) {
            headers['Range'] = rangeHeader
          }

          const response = await fetch(endpoint, {
            headers: headers,
            redirect: 'follow'
          })

          const contentType = response.headers.get('content-type') || ''
          const contentLength = parseInt(response.headers.get('content-length') || '0')

          // Success: non-HTML response
          if ((response.ok || response.status === 206) && !contentType.includes('text/html')) {
            // Proxy all important headers
            const proxyHeaders = new Headers()
            
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
              const value = response.headers.get(header)
              if (value) proxyHeaders.set(header, value)
            })

            // Add CORS headers
            proxyHeaders.set('Access-Control-Allow-Origin', '*')
            proxyHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
            proxyHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges')

            return new Response(response.body, {
              status: response.status,
              headers: proxyHeaders
            })
          }

          // If HTML and small, it's an error page - try next method
          if (contentType.includes('text/html') && contentLength < 50000) {
            continue
          }

        } catch (error) {
          // Try next combination
          continue
        }
      }
    }

    // All methods failed
    return new Response(JSON.stringify({ 
      error: 'Download failed',
      message: 'Unable to download file. Make sure the file is publicly shared (Anyone with the link can view).',
      fileId: fileId
    }), {
      status: 404,
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
