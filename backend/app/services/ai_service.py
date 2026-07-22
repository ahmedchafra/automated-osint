import os
from typing import Optional

from groq import Groq
from app.config import settings


class AIService:
    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.model = "llama-3.3-70b-versatile"  # Fast, high-quality model
        self._client: Optional[Groq] = None

    @property
    def client(self) -> Groq:
        if self._client is None:
            if not self.api_key:
                raise ValueError("GROQ_API_KEY is not set")
            self._client = Groq(api_key=self.api_key)
        return self._client

    def generate_dork(self, user_prompt: str) -> str:
        """
        Convert a natural language recon request into a Google Dork.
        Uses Groq's Llama 3 70B model with a system prompt tuned for OSINT.
        """
        system_prompt = """You are an OSINT expert specializing in Google Dorking.
        Convert the user's natural language request into a precise Google Dork query.
        Rules:
        - Use only Google Dork syntax (site:, inurl:, intitle:, filetype:, etc.)
        - Do NOT include explanations or extra text—output ONLY the dork string
        - Focus on finding exposed resources, login panels, config files, docs, etc.
        - If the request is vague, assume they want to find login portals or admin interfaces
        - Keep the dork under 200 characters if possible
        - Examples:
          User: "Find exposed login pages for example.com"
          Dork: site:example.com inurl:login | site:example.com intitle:"Sign in"
          User: "Find PDF documents on example.com"
          Dork: site:example.com filetype:pdf
          User: "Find admin directories"
          Dork: intitle:"admin" inurl:admin
        """

        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.model,
                temperature=0.3,  # Low temperature for more deterministic output
                max_tokens=100,
                top_p=0.9,
                stream=False,
            )
            dork = chat_completion.choices[0].message.content.strip()
            # Ensure we return a non-empty string
            if not dork:
                # Fallback to a simple site: search
                return f"site:{user_prompt.split()[-1]}"
            return dork
        except Exception as e:
            # Fallback: if Groq fails, return a simple site: search based on the last word
            # (assuming the prompt ends with a domain)
            words = user_prompt.strip().split()
            if words:
                potential_domain = words[-1]
                # Basic validation: looks like a domain
                if "." in potential_domain and not potential_domain.startswith("."):
                    return f"site:{potential_domain}"
            # Ultimate fallback
            return f"site:{user_prompt}"