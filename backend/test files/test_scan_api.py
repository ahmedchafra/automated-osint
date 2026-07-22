"""Test scan API endpoints to debug "Failed to load scan" error."""
import httpx, asyncio

async def check():
    async with httpx.AsyncClient(base_url='http://localhost:8000') as c:
        r = await c.post('/api/auth/login', json={'username':'admin','password':'admin123'})
        token = r.json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}

        sid = 'dc04fead-5841-4057-a088-59fc34221441'

        # Test GET /api/scans/{id}
        r = await c.get(f'/api/scans/{sid}', headers=headers)
        print(f'GET /api/scans/{{id}}: {r.status_code}')
        if r.status_code == 200:
            d = r.json()
            print(f'  target_domain={d.get("target_domain")} status={d.get("status")}')
            print(f'  owner_id={d.get("owner_id")}')
        else:
            print(f'  {r.text[:500]}')

        # Test permissions
        r = await c.get(f'/api/scans/{sid}/permissions', headers=headers)
        print(f'GET /api/scans/{{id}}/permissions: {r.status_code} {r.text[:200]}')

asyncio.run(check())
