'use strict';

// Capture only bounded GET responses.  The caller supplies a fine-grained
// observer token with repository Administration:read, never the deploy key or
// a maintainer signing key.  The Python verifier owns all policy decisions.

const fs = require('fs');

const API_VERSION = '2026-03-10';
const MAX_PAGES = 10;
const MAX_RULESETS = 100;

function fail(message) {
  throw new Error(`release source protection capture failed: ${message}`);
}

function canonicalPositiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/.test(value || '')) {
    fail(`${label} must be a canonical positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail(`${label} is outside the safe integer range`);
  }
  return parsed;
}

async function boundedPages(github, route, parameters, label) {
  const items = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const response = await github.request(route, {
      ...parameters,
      per_page: 100,
      page,
      headers: {
        accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': API_VERSION,
      },
    });
    if (response.status !== 200 || !Array.isArray(response.data)) {
      fail(`${label} did not return one array with HTTP 200`);
    }
    items.push(...response.data);
    if (response.data.length < 100) {
      return {complete: true, pages: page, items};
    }
  }
  fail(`${label} exceeds ${MAX_PAGES * 100} items`);
}

async function get(github, route, parameters, label) {
  const response = await github.request(route, {
    ...parameters,
    headers: {
      accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': API_VERSION,
    },
  });
  if (response.status !== 200 || !response.data || typeof response.data !== 'object') {
    fail(`${label} did not return one object with HTTP 200`);
  }
  return response.data;
}

function normalizeRule(raw) {
  if (!raw || typeof raw !== 'object') {
    fail('rule is not an object');
  }
  const rule = {type: raw.type};
  if (raw.type === 'pull_request') {
    const parameters = raw.parameters || {};
    rule.parameters = {
      allowed_merge_methods: parameters.allowed_merge_methods,
      dismissal_restriction: parameters.dismissal_restriction ?? null,
      dismiss_stale_reviews_on_push: parameters.dismiss_stale_reviews_on_push,
      require_code_owner_review: parameters.require_code_owner_review,
      require_last_push_approval: parameters.require_last_push_approval,
      required_approving_review_count: parameters.required_approving_review_count,
      required_reviewers: parameters.required_reviewers ?? [],
      required_review_thread_resolution: parameters.required_review_thread_resolution,
    };
  } else if (raw.type === 'required_status_checks') {
    const parameters = raw.parameters || {};
    rule.parameters = {
      do_not_enforce_on_create: parameters.do_not_enforce_on_create,
      strict_required_status_checks_policy: parameters.strict_required_status_checks_policy,
      required_status_checks: Array.isArray(parameters.required_status_checks)
        ? parameters.required_status_checks.map(item => ({
          context: item?.context,
          integration_id: item?.integration_id,
        }))
        : parameters.required_status_checks,
    };
  }
  if (Object.hasOwn(raw, 'ruleset_id')) {
    rule.ruleset_id = raw.ruleset_id;
    rule.ruleset_source_type = raw.ruleset_source_type;
    rule.ruleset_source = raw.ruleset_source;
  }
  return rule;
}

function normalizeRuleset(raw) {
  if (!raw || typeof raw !== 'object') {
    fail('ruleset detail is not an object');
  }
  return {
    id: raw.id,
    name: raw.name,
    target: raw.target,
    source_type: raw.source_type,
    source: raw.source,
    enforcement: raw.enforcement,
    bypass_actors: Array.isArray(raw.bypass_actors)
      ? raw.bypass_actors.map(item => ({
        actor_id: item?.actor_id,
        actor_type: item?.actor_type,
        bypass_mode: item?.bypass_mode,
      }))
      : raw.bypass_actors,
    conditions: {
      ref_name: {
        include: raw.conditions?.ref_name?.include,
        exclude: raw.conditions?.ref_name?.exclude,
      },
    },
    rules: Array.isArray(raw.rules) ? raw.rules.map(normalizeRule) : raw.rules,
  };
}

function normalizeDeployKey(raw) {
  if (!raw || typeof raw !== 'object') {
    fail('deploy-key entry is not an object');
  }
  return {
    id: raw.id,
    key: raw.key,
    title: raw.title,
    verified: raw.verified,
    read_only: raw.read_only,
    enabled: raw.enabled,
  };
}

module.exports = async function captureReleaseSourceProtection({
  github,
  context,
  outputPath,
  expectedRulesetId,
}) {
  const rulesetId = canonicalPositiveInteger(expectedRulesetId, 'expected ruleset ID');
  const {owner, repo} = context.repo;
  if (owner !== 'EvoRiseKsa' || repo !== 'EvoOM-Guard-m') {
    fail('workflow repository is not the frozen release repository');
  }
  const common = {owner, repo};
  const startedAt = new Date().toISOString().replace(/\.[0-9]{3}Z$/, 'Z');
  const actorRaw = await get(github, 'GET /user', {}, 'authenticated actor');
  const repositoryRaw = await get(
    github,
    'GET /repos/{owner}/{repo}',
    common,
    'repository',
  );
  const branchRaw = await get(
    github,
    'GET /repos/{owner}/{repo}/branches/{branch}',
    {...common, branch: 'main'},
    'main branch',
  );

  let classicStatus;
  try {
    const classic = await github.request(
      'GET /repos/{owner}/{repo}/branches/{branch}/protection',
      {
        ...common,
        branch: 'main',
        headers: {
          accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': API_VERSION,
        },
      },
    );
    classicStatus = classic.status;
  } catch (error) {
    if (error && error.status === 404) {
      classicStatus = 404;
    } else {
      throw error;
    }
  }

  const summaries = await boundedPages(
    github,
    'GET /repos/{owner}/{repo}/rulesets',
    {...common, includes_parents: true, targets: 'branch,push'},
    'branch/push ruleset listing',
  );
  if (summaries.items.length > MAX_RULESETS) {
    fail(`branch/push ruleset inventory exceeds ${MAX_RULESETS}`);
  }
  const seenRulesets = new Set();
  const details = [];
  for (const summary of summaries.items) {
    if (!summary || typeof summary !== 'object' ||
        !Number.isSafeInteger(summary.id) || summary.id < 1 ||
        seenRulesets.has(summary.id)) {
      fail('branch/push ruleset summary contains an invalid or duplicate ID');
    }
    seenRulesets.add(summary.id);
    details.push(normalizeRuleset(await get(
      github,
      'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}',
      {...common, ruleset_id: summary.id, includes_parents: true},
      `ruleset ${summary.id}`,
    )));
  }
  const mainRuleset = details.find(item => item.id === rulesetId);
  if (!mainRuleset) {
    fail('expected main ruleset is absent from the complete branch/push listing');
  }

  const applicableRaw = await boundedPages(
    github,
    'GET /repos/{owner}/{repo}/rules/branches/{branch}',
    {...common, branch: 'main'},
    'applicable main rules',
  );
  const deployKeysRaw = await boundedPages(
    github,
    'GET /repos/{owner}/{repo}/keys',
    common,
    'deploy-key listing',
  );
  const observedAt = new Date().toISOString().replace(/\.[0-9]{3}Z$/, 'Z');
  const snapshot = {
    format: 'EVOGUARD_RELEASE_SOURCE_PROTECTION_SNAPSHOT_V1',
    api_version: API_VERSION,
    started_at: startedAt,
    observed_at: observedAt,
    authenticated_actor: {
      login: actorRaw.login,
      id: actorRaw.id,
      type: actorRaw.type,
    },
    repository: {
      full_name: repositoryRaw.full_name,
      id: repositoryRaw.id,
      default_branch: repositoryRaw.default_branch,
      fork: repositoryRaw.fork,
      owner: {
        login: repositoryRaw.owner?.login,
        id: repositoryRaw.owner?.id,
        type: repositoryRaw.owner?.type,
      },
    },
    main_branch: {
      name: branchRaw.name,
      sha: branchRaw.commit?.sha,
      protected: branchRaw.protected,
    },
    classic_main_branch_protection: {status: classicStatus},
    branch_and_push_rulesets: {
      complete: summaries.complete,
      pages: summaries.pages,
      items: details,
    },
    main_ruleset: mainRuleset,
    applicable_main_rules: {
      complete: applicableRaw.complete,
      pages: applicableRaw.pages,
      items: applicableRaw.items.map(normalizeRule),
    },
    deploy_keys: {
      complete: deployKeysRaw.complete,
      pages: deployKeysRaw.pages,
      items: deployKeysRaw.items.map(normalizeDeployKey),
    },
  };
  fs.writeFileSync(outputPath, JSON.stringify(snapshot) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
};
