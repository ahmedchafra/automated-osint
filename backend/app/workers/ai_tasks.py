from typing import Optional

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run, persist_findings
from app.services.ai_service import AIService
from collectors.registry import registry
from app.models.ai_query import AIQuery
from app.models.scan import Scan


@celery_app.task(name="run_ai_dork_task", bind=True, max_retries=2, default_retry_delay=5)
def run_ai_dork_task(self, scan_id: str, user_prompt: str):
    """
    Celery task to generate a Google Dork from a natural language prompt,
    execute the dork via Serper.dev, and store the results.
    """
    async def run_task():
        async with AsyncSessionLocal() as session:
            # 1. Verify the scan exists
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            # 2. Generate the dork using AI service
            ai_service = AIService()
            try:
                dork = ai_service.generate_dork(user_prompt)
            except Exception as e:
                # If AI service fails, fallback to a simple site: search
                # Extract the last word that looks like a domain
                import re
                words = user_prompt.strip().split()
                domain = None
                for w in reversed(words):
                    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z]{2,})+$', w):
                        domain = w
                        break
                if domain:
                    dork = f"site:{domain}"
                else:
                    dork = f"site:{user_prompt}"

            # 3. Execute the dork via Serper
            serper_cls = registry.get_collector("serper_dork_search")
            serper_collector = serper_cls()
            search_results = await serper_collector.execute(dork)

            # 5. Persist the search results as DORK_RESULT findings so the
            # findings table, correlation engine, and exports all see them
            # the same way they see any other collector output.
            await persist_findings(
                session,
                scan_id,
                search_results,
                default_vector="SEARCH",
                default_severity="INFO",
                default_confidence=0.7,
            )

            # 6. Store an AIQuery record for the AIAssistant UI timeline.
            ai_query = AIQuery(
                scan_id=scan_id,
                user_prompt=user_prompt,
                generated_dork=dork,
                model_used=ai_service.model,
                search_results=[
                    {
                        "title": r.get("title"),
                        "link": r.get("link"),
                        "snippet": r.get("snippet"),
                        "position": r.get("position"),
                    }
                    for r in search_results
                    if r.get("link")
                ],
            )
            session.add(ai_query)
            await session.commit()

            return {
                "scan_id": scan_id,
                "dork": dork,
                "results_found": len(search_results),
            }

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
