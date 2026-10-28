import { ExternalLink } from 'lucide-react';
import type { GithubRepositoryEvidence } from './githubEvidence';

export function GithubRepositoryTable({ repositories }: { repositories: GithubRepositoryEvidence[] }) {
  return (
    <div className="table-container">
      <table>
        <thead><tr><th>Repository</th><th>Description</th><th>Stars</th><th>Language</th></tr></thead>
        <tbody>
          {repositories.map(repo => (
            <tr key={repo.id}>
              <td className="font-mono">
                {repo.repoUrl ? (
                  <a className="ws-repo-link" href={repo.repoUrl} target="_blank" rel="noreferrer">
                    {repo.repoName} <ExternalLink size={11} />
                  </a>
                ) : repo.repoName}
              </td>
              <td className="text-gray ws-repo-description">{repo.description || '—'}</td>
              <td className="text-gray">{repo.stars.toLocaleString()}</td>
              <td className="text-gray">{repo.language}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
