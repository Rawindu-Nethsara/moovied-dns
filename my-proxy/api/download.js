// api/download.js
// Deploy to Vercel: https://vercel.com

export const config = {
  runtime: 'edge',
}

export default async function handler(request) {
  // CORS
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Range',
      }
    })
  }

  const { searchParams } = new URL(request.url)
  const fileId = searchParams.get('id')

  if (!fileId) {
    return new Response(JSON.stringify({ error: 'Missing file ID' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  try {
    // Try multiple Google Drive endpoints
    const urls = [
      `https://drive.usercontent.google.com/download?id=${fileId}&export=download&authuser=0&confirm=t`,
      `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
      `https://docs.google.com/uc?export=download&id=${fileId}&confirm=t`
    ]

    for (const url of urls) {
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Referer': 'https://drive.google.com/'
        }
      })

      const contentType = response.headers.get('content-type') || ''
      
      if (response.ok && !contentType.includes('text/html')) {
        const headers = new Headers(response.headers)
        headers.set('Access-Control-Allow-Origin', '*')
        
        return new Response(response.body, {
          status: response.status,
          headers: headers
        })
      }
    }

    return new Response(JSON.stringify({ error: 'Download failed' }), {
      status: 404,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    })
  }
}
