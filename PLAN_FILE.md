# Real-Time Scan Results Streaming

## Problem

The initial scan (Phase 1) takes 2-5 minutes for most targets (crt.sh + subfinder + theHarvester + DNS resolution + Shodan InternetDB + WhoIS). During this entire period, the user stares at a blank scan workspace with zero feedback. Findings only appear after `refetchInterval: 8_000` polling kicks in, and the first visible batch arrives only after the first tool finishes **and** the 8-second poll fires.

## Goal

- Show findings **as each tool completes** — not when all tools finish
- Show the **scan progress** visually (which phase, which tool, what's next)
- Tab badges update in real-time as new findings arrive
- No more than 1-second delay between a tool persisting findings and them appearing in the UI

## Existing Infrastructure (already in place)

| Component | What it does | File |
|-----------|-------------|------|
| `ScanProgressPublisher.publish()` | Pushes events to Redis pubsub channel `scan:{scan_id}` | `backend/app/services/progress.py` |
| `RedisScanEventStreamer.stream()` | Listens on Redis pubsub and forwards to WebSocket | `backend/app/services/streaming.py` |
| `GET /ws/scans/{scan_id}` | WebSocket endpoint accepting API key auth | `backend/app/api/ws.py` |
| `openScanWebSocket()` | Frontend WS helper with auto-reconnect | `frontend/src/api/ws.ts` |
| `GET /api/findings/?scan_id=X` | Paginated findings API with `total` count | `backend/app/api/findings.py` |
| Scan pipeline persists after each tool | `_run_tool()` → `persist_findings()` → findings in DB immediately | `backend/app/workers/initial_scan.py` |

## The Gap

The WebSocket already delivers `tool_completed` events during the initial scan. But:

1. The findings poll (`refetchInterval: 8_000`) is on a fixed timer — receiving `tool_completed` doesn't trigger an immediate refetch
2. The pipeline view in the workspace shows generic status but doesn't list individual tools or their timing
3. The scan view starts with no indication of what's happening or how far along the scan is

---

## Implementation Plan

### 1. Frontend: Trigger Immediate Findings Refetch on `tool_completed`

**File:** `frontend/src/pages/ScanWorkspace.tsx`

**Change:** In the WebSocket handler in `ResultsViewWithTabs`, add a case for `tool_completed` that invalidates the findings query so it refetches immediately:

```tsx
case 'tool_completed':
  // A tool just finished — invalidate findings query for instant refetch
  queryClient.invalidateQueries({ queryKey: ['scanFindings', scanId] });
  break;
```

**Why it works:**
- React Query sees the invalidation and immediately refetches findings (no waiting for the next poll cycle)
- The findings API already returns all persisted findings with the correct `total`
- `state.findings` is updated via the existing `useEffect([findingsResponse])` pipeline
- Tab badges recalculate via the existing `useMemo(() => tabCounts, [state.findings])`

**Cost:** +6 lines of code

### 2. Frontend: Add `queryClient` Reference

**File:** `frontend/src/pages/ScanWorkspace.tsx`

**Change:** The `ResultsViewWithTabs` component needs access to `queryClient` to call `invalidateQueries`. At the top of the component:

```tsx
const queryClient = useQueryClient();
```

**Already imported?** Check if `useQueryClient` is imported from `@tanstack/react-query` — if not, add it.

**Why useQueryClient instead of a state setter:**
- The findings are already loaded via `useQuery` with query key `['scanFindings', scanId]`
- `invalidateQueries` is the canonical React Query way to trigger an immediate refetch
- It integrates cleanly with all existing `useQuery` hooks (no new state management)

**Note:** If `webSocketRef` and the polling logic are in different components (e.g., `PipelineView` vs `ResultsViewWithTabs`), we need to wire the invalidation into whichever component owns the WS handler that receives `tool_completed`.

### 3. Frontend: Reduce Baseline Poll Frequency

**File:** `frontend/src/pages/ScanWorkspace.tsx`

**Change:** Once `tool_completed` triggers instant refetches, we don't need to poll as aggressively. Change:

```typescript
refetchInterval: 8_000,  // before
```
to:
```typescript
refetchInterval: scanStatus === 'RUNNING' ? 15_000 : 8_000,  // after
```

The 15-second poll is a safety net (catches any edge cases where the WS event was missed). When the scan finishes, go back to 8 seconds for picking up deep-analysis results.

**However:** This is optional — 8 seconds was fine. The real win is the instant WS-triggered refetch.

### 4. Frontend: Pipeline Progress Panel (WebSocket Phase)

**File:** `frontend/src/components/workspace/PipelineProgress.tsx` (new file)

Create a live status panel shown in the workspace while scan.status === 'RUNNING'. It displays:

```
Phase 1/4: INFRASTRUCTURE
  ✅ crt.sh          (23s, 3,472 findings)
  ⏳ subfinder       (running...)
  ⏸ theHarvester
  ⏸ DNS Resolution
  ⏸ Shodan InternetDB
  ⏸ WhoIS / ASN

Phase 2/4: SERVICES
  ⏸ Shodan Host
  ⏸ Censys
  ⏸ NVD CVE
  ⏸ CISA KEV
...
```

**WebSocket events consumed:**
- `phase_started` → create phase section, mark tools as pending
- `tool_started` → set that tool's status to "running" with start time
- `tool_completed` → set status to "completed" with elapsed time + findings count
- `tool_error` / `tool_timeout` → set status to "failed" with error message
- `phase_completed` → collapse/summarize phase
- `scan_completed` → show final summary, optionally auto-hide the panel

**State tracked in component local `useState`:**
```typescript
interface ToolStatus {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'timeout';
  startedAt?: number;
  elapsedSeconds?: number;
  findingsCount?: number;
  error?: string;
}
interface PhaseStatus {
  name: string;
  index: number;
  tools: Record<string, ToolStatus>;
  completed: boolean;
}
```

**Integration point in `ScanWorkspace.tsx`:**
- During the `PipelineView` phase (before scan completes), render `<PipelineProgress />` alongside or instead of the basic spinner
- The existing WS connection in `PipelineView` is already set up — just need to feed events into the new component

### 5. Frontend: Show Live Finding Count in Nav

**File:** `frontend/src/pages/ScanWorkspace.tsx`

**Change:** The scan header already shows total findings. Make it update live:

```tsx
// Before (static from scan metadata):
<span>{scan?.findings_count ?? 0} findings</span>

// After (live from state):
<span>{state.findings.length} findings</span>
```

And add a "Last updated: just now" indicator that shows when the last `tool_completed` was received.

### 6. (Optional) Backend: Findings-Per-Tool in `tool_completed` Event

**File:** `backend/app/workers/initial_scan.py`

**Change:** The `tool_completed` event already includes `collected` (raw findings count). Consider adding `persisted` (new rows actually saved):

```python
await publisher.publish(scan_id, "tool_completed", {
    "tool": collector_name,
    "target": target,
    "collected": len(findings),
    "persisted": new_findings_count,  # <- add this
    "elapsed_seconds": round(elapsed, 1),
})
```

**But:** This requires modifying the existing pipeline to return the persisted count. The `_run_tool` function currently returns findings but doesn't know how many were newly persisted (that happens in the pipeline's `persist_findings()` call). The pipeline would need to thread this value back. Moderate complexity for a small UX win — the frontend already has `total` from the API response.

**Decision: Defer.** The frontend can count `state.findings.length` directly, which is more accurate than per-tool counts anyway.

---

## Data Flow After Implementation

```
Worker (initial_scan.py):
  crt.sh completes → persist_findings() → publish(tool_completed)
  subfinder completes → persist_findings() → publish(tool_completed)
  ...

Redis pubsub (channel: scan:{scan_id}):
  {event: "tool_completed", tool: "crtsh", collected: 3472, ...}

Backend WebSocket (/ws/scans/{scan_id}):
  Forwards event → browser

Frontend ScanWorkspace:
  WS receives "tool_completed"
  → queryClient.invalidateQueries(['scanFindings', scanId])
  → useQuery refetches GET /api/findings/?scan_id=X&limit=1000
  → dispatch(FINDINGS_UPDATED, new findings)
  → state.findings updates
  → tab badges recalculate
  → user sees new data

  Total time from tool completion to UI update: < 1 second
```

---

## Files to Modify

1. **`frontend/src/pages/ScanWorkspace.tsx`** — Add `useQueryClient()`, handle `tool_completed` in the WebSocket event handler to invalidate findings query, show live findings count

2. **`frontend/src/components/workspace/PipelineProgress.tsx`** — New file: live pipeline progress panel showing phases, tools, timing

3. **`frontend/src/pages/ScanWorkspace.tsx`** (integration) — Mount `<PipelineProgress />` during the pipeline execution phase

---

## What This Does NOT Change

- The backend pipeline logic (no changes to `initial_scan.py`, `task_utils.py`, `progress.py`)
- The findings API endpoint
- The WebSocket endpoint or streaming service
- The Redis pubsub event schema
- The ScanWorkspaceContext state model
- The InfrastructureTab or any other tab component

---

## Verification

1. Start a scan against cloudflare.com
2. Observe the PipelineProgress panel showing live tool status
3. Note: findings appear in the tab badges within 1 second of each tool completing (not 8 seconds)
4. Verify: no duplicate findings after the poll+WS cycle (dedup is handled in `persist_findings` and React Query's cache)
5. Verify: tab content renders correctly (Infrastructure tab shows TLS_CERT, HOST_METADATA, etc.)
6. TypeScript: `npx tsc --noEmit` — zero errors
7. Edge case: WebSocket disconnects mid-scan — the 15-second safety poll catches any missed events
