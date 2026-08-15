'use strict';

// Capture GitHub-hosted push-run timestamps for the exact freeze-declaration
// commit.  These server timestamps prevent an owner-controlled Git commit date
// from being treated as the start of the fourteen-day stabilization window.

const fs = require('fs');

const API_VERSION = '2026-03-10';
const MAX_PAGES = 10;

function fail(message) {
  throw new Error(`minor-release freeze anchor capture failed: ${message}`);
}

module.exports = async function captureMinorReleaseFreezeAnchor({
  github,
  context,
  declarationSha,
  declarationTreeSha,
  outputPath,
}) {
  if (!/^[0-9a-f]{40}$/.test(declarationSha || '') ||
      !/^[0-9a-f]{40}$/.test(declarationTreeSha || '')) {
    fail('declaration commit/tree must be full lowercase Git IDs');
  }
  const {owner, repo} = context.repo;
  if (owner !== 'EvoRiseKsa' || repo !== 'EvoOM-Guard-m') {
    fail('workflow repository is not the frozen release repository');
  }
  const items = [];
  let totalCount = null;
  let pages = 0;
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const response = await github.request(
      'GET /repos/{owner}/{repo}/actions/runs',
      {
        owner,
        repo,
        branch: 'main',
        event: 'push',
        head_sha: declarationSha,
        exclude_pull_requests: true,
        per_page: 100,
        page,
        headers: {
          accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': API_VERSION,
        },
      },
    );
    const data = response.data;
    if (response.status !== 200 || !data || typeof data !== 'object' ||
        !Number.isSafeInteger(data.total_count) || data.total_count < 0 ||
        !Array.isArray(data.workflow_runs)) {
      fail('workflow-run search did not return a bounded HTTP-200 result');
    }
    if (totalCount === null) {
      totalCount = data.total_count;
      if (totalCount > MAX_PAGES * 100) {
        fail('workflow-run search exceeds the GitHub 1000-result bound');
      }
    } else if (data.total_count !== totalCount) {
      fail('workflow-run result count changed during pagination');
    }
    pages = page;
    items.push(...data.workflow_runs);
    if (data.workflow_runs.length < 100) {
      break;
    }
    if (page === MAX_PAGES) {
      fail('workflow-run pagination did not terminate inside the bound');
    }
  }
  if (items.length !== totalCount || totalCount < 1) {
    fail('workflow-run inventory is incomplete or empty');
  }
  const observedAt = new Date().toISOString().replace(/\.[0-9]{3}Z$/, 'Z');
  const snapshot = {
    format: 'EVOGUARD_MINOR_RELEASE_FREEZE_GITHUB_ANCHOR_SNAPSHOT_V1',
    api_version: API_VERSION,
    observed_at: observedAt,
    repository: `${owner}/${repo}`,
    repository_id: String(context.payload.repository.id),
    declaration_commit_sha: declarationSha,
    declaration_tree_sha: declarationTreeSha,
    query: {
      branch: 'main',
      event: 'push',
      head_sha: declarationSha,
      exclude_pull_requests: true,
      per_page: 100,
    },
    workflow_runs: {
      complete: true,
      pages,
      total_count: totalCount,
      items: items.map(run => ({
        id: String(run.id),
        run_attempt: run.run_attempt,
        workflow_id: String(run.workflow_id),
        name: run.name,
        path: run.path,
        event: run.event,
        head_branch: run.head_branch,
        head_sha: run.head_sha,
        status: run.status,
        conclusion: run.conclusion,
        created_at: run.created_at,
        updated_at: run.updated_at,
        repository_id: String(run.repository?.id),
        head_repository_id: String(run.head_repository?.id),
      })),
    },
  };
  fs.writeFileSync(outputPath, JSON.stringify(snapshot) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
};
