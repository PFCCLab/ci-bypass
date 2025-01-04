import * as core$1 from "@actions/core";
import * as core from "@actions/core";
import { context, getOctokit } from "@actions/github";

//#region src/composite.ts
function isAnyComposite(composite) {
	return composite.any !== undefined;
}
function isAllComposite(composite) {
	return composite.all !== undefined;
}
function isNotComposite(composite) {
	return composite.not !== undefined;
}
function resolveCompositeAnyAsync(predicate) {
	return async (composite) => {
		const results = await Promise.all(composite.any.map(async (value) => await predicate(value)));
		return results.some((value) => value);
	};
}
function resolveCompositeAllAsync(predicate) {
	return async (composite) => {
		const results = await Promise.all(composite.all.map(async (value) => await predicate(value)));
		return results.every((value) => value);
	};
}
function resolveCompositeNotAsync(predicate) {
	return async (composite) => !await predicate(composite.not);
}
function resolveCompositeAsync(predicate) {
	async function predicateForComposite(value) {
		return resolveCompositeAsync(predicate)(value);
	}
	return async (composite) => {
		if (isAnyComposite(composite)) return resolveCompositeAnyAsync(predicateForComposite)(composite);
else if (isAllComposite(composite)) return resolveCompositeAllAsync(predicateForComposite)(composite);
else if (isNotComposite(composite)) return resolveCompositeNotAsync(predicateForComposite)(composite);
else return await predicate(composite);
	};
}

//#endregion
//#region src/rules/check.ts
var ByPassChecker = class {
	ruleClasses;
	constructor(ruleClasses) {
		this.ruleClasses = ruleClasses;
	}
	async check(rule, context$1) {
		if (!rule || typeof rule !== "object" || !rule.type) throw new Error(`Invalid rule object ${JSON.stringify(rule)}`);
		const ruleInstance = this.getRuleClass(rule.type)?.fromObject(rule);
		if (!ruleInstance) throw new Error(`Unsupported rule type: ${rule.type}`);
		return await ruleInstance.check(context$1);
	}
	getRuleClass(type) {
		return this.ruleClasses.get(type);
	}
};
var ByPassCheckerBuilder = class {
	ruleClasses = new Map();
	constructor() {}
	use(ruleClass) {
		this.ruleClasses.set(ruleClass.type, ruleClass);
		return this;
	}
	build() {
		return new ByPassChecker(this.ruleClasses);
	}
};

//#endregion
//#region src/rules/base.ts
var AbstractRule = class {
	static type;
	static fromObject(obj) {
		throw new Error("fromObject method must be implemented");
	}
};

//#endregion
//#region src/rules/label.ts
function resolveOneOrMoreOption(value) {
	return Array.isArray(value) ? value : [value];
}
function resolveMaybeOneOrMoreOption(value) {
	return value ? resolveOneOrMoreOption(value) : [];
}
var LabelRule = class LabelRule extends AbstractRule {
	static type = "labeled";
	labels;
	userNames;
	userTeams;
	constructor(label, userName, userTeam) {
		super();
		this.labels = resolveOneOrMoreOption(label);
		this.userNames = resolveMaybeOneOrMoreOption(userName);
		this.userTeams = resolveMaybeOneOrMoreOption(userTeam);
	}
	async check(context$1) {
		const { githubToken, githubContext } = context$1;
		const octokit = getOctokit(githubToken);
		const { owner, repo } = githubContext.repo;
		const { number } = githubContext.issue;
		const allEventsResponse = await octokit.rest.issues.listEvents({
			owner,
			repo,
			issue_number: number
		});
		const allLabelsResponse = await octokit.rest.issues.listLabelsOnIssue({
			owner,
			repo,
			issue_number: number
		});
		const currentLabels = allLabelsResponse.data.map((label) => label.name).filter((label) => this.labels.includes(label));
		const labeledEvents = allEventsResponse.data.filter((event) => event.event === "labeled");
		const isValidLabeledUserByName = async (currentEventUserName, allowUserNames) => {
			if (allowUserNames.length === 0) return true;
			const result = allowUserNames.includes(currentEventUserName);
			if (!result) core$1.info(`user ${currentEventUserName} not in allowUserNames`);
			return result;
		};
		const isValidLabeledUserByTeam = async (currentEventUserName, allowUserTeams) => {
			if (allowUserTeams.length === 0) return true;
			return await Promise.all(allowUserTeams.map(async (team) => {
				try {
					const { data: teamMembers } = await octokit.rest.teams.listMembersInOrg({
						org: owner,
						team_slug: team
					});
					return teamMembers.map((member) => member.login);
				} catch (error) {
					core$1.error(`Error in get teamMembers ${team} in ${owner}, check your token has org:read permission`);
					throw error;
				}
			})).then((results) => {
				const result = results.some((members) => members.includes(currentEventUserName));
				if (!result) core$1.info(`user ${currentEventUserName} not in allowUserTeams ${allowUserTeams}`);
				return result;
			});
		};
		const isValidLabel = async (label) => {
			for (const labeledEvent of labeledEvents.reverse()) if ("label" in labeledEvent && labeledEvent.label.name === label) {
				const currentEventUserName = labeledEvent.actor.login;
				return await isValidLabeledUserByName(currentEventUserName, this.userNames) || await isValidLabeledUserByTeam(currentEventUserName, this.userTeams);
			}
			core$1.error(`label ${label} not found in labeledEvents`);
			return false;
		};
		core$1.debug(`labeledEvents: ${JSON.stringify(labeledEvents)}`);
		core$1.debug(`currentLabels: ${JSON.stringify(currentLabels)}`);
		return await Promise.all(currentLabels.map(isValidLabel)).then((results) => results.some(Boolean));
	}
	static fromObject(obj) {
		return new LabelRule(obj.label, obj["username"], obj["user-team"]);
	}
};

//#endregion
//#region src/main.ts
function parseArrayInput(input, separator) {
	return input.split(separator).map((item) => item.trim());
}
function parseRuleRawObjectFromInput() {
	const type = core.getInput("type");
	switch (type) {
		case LabelRule.type: return {
			type: LabelRule.type,
			label: parseArrayInput(core.getInput("label"), "|"),
			username: parseArrayInput(core.getInput("username"), "|"),
			"user-team": parseArrayInput(core.getInput("user-team"), "|")
		};
		case "composite": return JSON.parse(core.getInput("composite-rule"));
		default: throw new Error(`Invalid rule type: ${type}`);
	}
}
async function run() {
	try {
		const githubToken = core.getInput("github-token");
		const rawRule = parseRuleRawObjectFromInput();
		core.info(`rawRule: ${JSON.stringify(rawRule)}`);
		async function check(value) {
			const bypassChecker = new ByPassCheckerBuilder().use(LabelRule).build();
			return bypassChecker.check(value, {
				githubToken,
				githubContext: context
			});
		}
		const result = await resolveCompositeAsync(check)(rawRule);
		core.info(`check result: ${result}`);
		core.setOutput("can-skip", result);
	} catch (error) {
		if (error instanceof Error) core.setFailed(error.message);
	}
}

//#endregion
//#region src/index.ts
run();

//#endregion