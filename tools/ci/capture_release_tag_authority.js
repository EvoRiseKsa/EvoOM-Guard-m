'use strict';

// Capture a bounded, read-only GitHub control-plane snapshot.  The caller must
// supply an Administration:read observer token, never either deploy private key.
// Policy decisions belong to validate_release_tag_authority.py.

const fs = require('fs');
const path = require('path');

const API_VERSION = '2026-03-10';
const MAX_PAGES = 10;
const MAX_RULESETS = 100;

function fail(message) {
  throw new Error(`release tag authority capture failed: ${message}`);
}

function canonicalize(value, label = 'snapshot') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      fail(`${label} contains a non-canonical number`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => canonicalize(item, `${label}[${index}]`));
  }
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(`${label} contains a value outside the JSON object model`);
  }
  const result = {};
  for (const key of Object.keys(value).sort()) {
    const item = value[key];
    if (item === undefined || typeof item === 'function' || typeof item === 'bigint') {
      fail(`${label}.${key} is not a JSON value`);
    }
    result[key] = canonicalize(item, `${label}.${key}`);
  }
  return result;
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
  if (
    response.status !== 200 ||
    !response.data ||
    typeof response.data !== 'object' ||
    Array.isArray(response.data)
  ) {
    fail(`${label} did not return one object with HTTP 200`);
  }
  return response.data;
}

function normalizeRule(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    fail('ruleset rule is not an object');
  }
  const result = {type: raw.type};
  if (raw.type === 'pull_request') {
    const parameters = raw.parameters || {};
    result.parameters = {
      allowed_merge_methods: parameters.allowed_merge_methods,
      dismissal_restriction: Object.hasOwn(parameters, 'dismissal_restriction')
        ? parameters.dismissal_restriction
        : null,
      dismiss_stale_reviews_on_push: parameters.dismiss_stale_reviews_on_push,
      require_code_owner_review: parameters.require_code_owner_review,
      require_last_push_approval: parameters.require_last_push_approval,
      required_approving_review_count: parameters.required_approving_review_count,
      required_review_thread_resolution: parameters.required_review_thread_resolution,
      required_reviewers: Object.hasOwn(parameters, 'required_reviewers')
        ? parameters.required_reviewers
        : [],
    };
  } else if (raw.type === 'required_status_checks') {
    const parameters = raw.parameters || {};
    result.parameters = {
      do_not_enforce_on_create: parameters.do_not_enforce_on_create,
      strict_required_status_checks_policy: parameters.strict_required_status_checks_policy,
      required_status_checks: Array.isArray(parameters.required_status_checks)
        ? parameters.required_status_checks
          .map(item => ({
            context: item?.context,
            integration_id: item?.integration_id,
          }))
          .sort((left, right) => {
            const leftContext = String(left.context);
            const rightContext = String(right.context);
            if (leftContext !== rightContext) {
              return leftContext < rightContext ? -1 : 1;
            }
            return Number(left.integration_id) - Number(right.integration_id);
          })
        : parameters.required_status_checks,
    };
  }
  return result;
}

function normalizeRuleset(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
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
      ? raw.bypass_actors
        .map(item => ({
          actor_id: item?.actor_id,
          actor_type: item?.actor_type,
          bypass_mode: item?.bypass_mode,
        }))
        .sort((left, right) => {
          const leftKey = `${String(left.actor_type)}\u0000${String(left.actor_id)}\u0000${String(left.bypass_mode)}`;
          const rightKey = `${String(right.actor_type)}\u0000${String(right.actor_id)}\u0000${String(right.bypass_mode)}`;
          return leftKey === rightKey ? 0 : (leftKey < rightKey ? -1 : 1);
        })
      : raw.bypass_actors,
    conditions: {
      ref_name: {
        include: Array.isArray(raw.conditions?.ref_name?.include)
          ? [...raw.conditions.ref_name.include].sort()
          : raw.conditions?.ref_name?.include,
        exclude: Array.isArray(raw.conditions?.ref_name?.exclude)
          ? [...raw.conditions.ref_name.exclude].sort()
          : raw.conditions?.ref_name?.exclude,
      },
    },
    rules: Array.isArray(raw.rules)
      ? raw.rules.map(normalizeRule).sort((left, right) => {
        const leftType = String(left.type);
        const rightType = String(right.type);
        return leftType === rightType ? 0 : (leftType < rightType ? -1 : 1);
      })
      : raw.rules,
  };
}

function normalizeDeployKey(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
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

async function rulesets(github, common, targets, label) {
  const summaries = await boundedPages(
    github,
    'GET /repos/{owner}/{repo}/rulesets',
    {...common, includes_parents: true, targets},
    `${label} listing`,
  );
  if (summaries.items.length > MAX_RULESETS) {
    fail(`${label} inventory exceeds ${MAX_RULESETS}`);
  }
  const identifiers = new Set();
  const details = [];
  for (const summary of summaries.items) {
    if (
      !summary ||
      typeof summary !== 'object' ||
      Array.isArray(summary) ||
      !Number.isSafeInteger(summary.id) ||
      summary.id < 1 ||
      identifiers.has(summary.id)
    ) {
      fail(`${label} summary contains an invalid or duplicate ID`);
    }
    identifiers.add(summary.id);
    const detail = await get(
      github,
      'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}',
      {...common, ruleset_id: summary.id, includes_parents: true},
      `${label} detail ${summary.id}`,
    );
    if (detail.id !== summary.id) {
      fail(`${label} summary/detail identity changed during capture`);
    }
    details.push(normalizeRuleset(detail));
  }
  details.sort((left, right) => left.id - right.id);
  return {complete: summaries.complete, pages: summaries.pages, items: details};
}

module.exports = async function captureReleaseTagAuthority({github, context, outputPath}) {
  const {owner, repo} = context.repo;
  if (owner !== 'EvoRiseKsa' || repo !== 'EvoOM-Guard-m') {
    fail('workflow repository is not the frozen release repository');
  }
  if (typeof outputPath !== 'string' || outputPath.length === 0) {
    fail('output path is not one non-empty string');
  }
  const parent = path.dirname(outputPath);
  const parentStatus = fs.lstatSync(parent);
  if (!parentStatus.isDirectory() || parentStatus.isSymbolicLink()) {
    fail('output parent must be an existing non-symlink directory');
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
  const branchAndPushRulesets = await rulesets(
    github,
    common,
    'branch,push',
    'branch/push ruleset',
  );
  const tagRulesets = await rulesets(github, common, 'tag', 'tag ruleset');
  const deployKeysRaw = await boundedPages(
    github,
    'GET /repos/{owner}/{repo}/keys',
    common,
    'deploy-key listing',
  );
  const deployKeys = deployKeysRaw.items
    .map(normalizeDeployKey)
    .sort((left, right) => left.id - right.id);
  const observedAt = new Date().toISOString().replace(/\.[0-9]{3}Z$/, 'Z');

  const snapshot = canonicalize({
    format: 'EVOGUARD_RELEASE_TAG_AUTHORITY_SNAPSHOT_V1',
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
    branch_and_push_rulesets: branchAndPushRulesets,
    tag_rulesets: tagRulesets,
    deploy_keys: {
      complete: deployKeysRaw.complete,
      pages: deployKeysRaw.pages,
      items: deployKeys,
    },
  });
  fs.writeFileSync(outputPath, `${JSON.stringify(snapshot)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
};
