import abc
import random
import asyncio
from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel

class CollectorMetadata(BaseModel):
    name: str
    vector: str
    description: str
    passive: bool
    requires_api_key: bool
    api_key_env: Optional[str] = None


class CollectorConfigurationError(RuntimeError):
    """Permanent collector setup/authentication failure.

    These failures must reach the job runner so the UI reports a failed job
    instead of presenting an empty result as a successful collection.
    """

class BaseCollector(abc.ABC):
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ]

    # Subclasses must override this
    metadata: CollectorMetadata = None

    @abc.abstractmethod
    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Collect data from the target."""
        pass

    @abc.abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize the raw data into the standard Finding format."""
        pass

    def get_random_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    async def execute(self, target: str) -> List[Dict[str, Any]]:
        """Wrapper method that handles retry logic, delays, and normalization.

        Transient upstream HTTP errors (5xx, timeouts, connection errors) are
        logged and treated as an empty result so a single flaky source does not
        fail the whole scan. Non-HTTP exceptions (logic bugs, missing keys)
        still propagate after exhausting retries.
        """
        max_retries = 5
        base_delay = 3

        for attempt in range(max_retries):
            try:
                # Add a small random jitter before starting to prevent burst patterns
                await asyncio.sleep(random.uniform(0.5, 1.5))

                raw_results = await self.collect(target)
                normalized_results = []

                for raw in raw_results:
                    normalized = self.normalize(raw)
                    normalized["source_module"] = self.metadata.name
                    normalized["vector_type"] = self.metadata.vector
                    normalized["raw_data"] = raw
                    normalized_results.append(normalized)

                return normalized_results

            except CollectorConfigurationError:
                # Retrying cannot fix a missing/rejected credential. Let the
                # tracked job persist the actionable error for the frontend.
                raise

            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
                # Transient transport-level issue: retry with backoff.
                name = getattr(self.metadata, "name", self.__class__.__name__)
                if attempt == max_retries - 1:
                    print(f"[{name}] upstream error after {max_retries} attempts, giving up: {e}")
                    return []
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(delay)

            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                # Retry only 429 (rate limit) and 5xx (server errors).
                # 4xx errors (401, 403, 404) are permanent — fail fast.
                if status == 429 or status >= 500:
                    name = getattr(self.metadata, "name", self.__class__.__name__)
                    if attempt == max_retries - 1:
                        print(f"[{name}] upstream error after {max_retries} attempts, giving up: {e}")
                        return []
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(delay)
                else:
                    name = getattr(self.metadata, "name", self.__class__.__name__)
                    print(f"[{name}] permanent HTTP {status} error, skipping retries: {e}")
                    return []

            except Exception as e:
                if attempt == max_retries - 1:
                    name = getattr(self.metadata, "name", self.__class__.__name__)
                    print(f"[{name}] non-recoverable error: {e}")
                    raise

                # Exponential backoff
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(delay)

        return []
