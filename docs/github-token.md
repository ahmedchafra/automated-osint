# GitHub Token Setup for Public Evidence Search

The GitHub collector searches public repository metadata and public code for
potential exposure indicators associated with the target. It requires
authentication because GitHub applies a separate, authenticated code-search
limit.

## Create a least-privilege token

1. Open [GitHub personal access tokens](https://github.com/settings/personal-access-tokens).
2. Create a **fine-grained** personal access token.
3. Give it a short expiration date.
4. Limit repository access to **Public repositories (read-only)**.
5. Do not add write permissions. GitHub's REST documentation states that the
   code-search endpoint supports fine-grained tokens and requires no additional
   fine-grained repository permission for public resources.

Do not use a classic token with the broad `repo` scope merely to search public
code. That scope grants private-repository access and is unnecessary for this
collector's intended public-evidence workflow.

Official references:

- [GitHub REST code-search endpoint](https://docs.github.com/en/rest/search/search#search-code)
- [Authenticating to the GitHub REST API](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api)

## Store it locally

Add the token only to `backend/.env`, which is excluded from Git:

```dotenv
GITHUB_TOKEN=github_pat_replace_with_your_token
```

Restart the API and worker after changing the environment:

```bash
docker compose restart backend worker
```

Never put a real token in documentation, source code, commits, chat messages,
issues, screenshots, command output, or frontend environment variables.

## If a token is exposed

1. Revoke it immediately in GitHub settings.
2. Review its recent use in the GitHub security log.
3. Remove it from local files or Git history if it was committed.
4. Create a replacement with a short lifetime and the minimum access above.

## Expected rate behavior

GitHub documents a separate limit for code search. The collector bounds each
query and rejects missing or invalid authentication. A rate-limited query can
currently return only the results gathered before the limit, so treat an empty
or shortened result set cautiously. Persisting an explicit `partial` or
`rate_limited` run outcome is the next reliability milestone described in the
main README.
