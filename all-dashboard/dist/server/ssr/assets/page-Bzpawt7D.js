import { a as require_react, o as __toESM, t as require_jsx_runtime } from "../index.js";
//#region app/page.tsx
var import_react = /* @__PURE__ */ __toESM(require_react(), 1);
var import_jsx_runtime = require_jsx_runtime();
var scannerMeta = {
	prowler: {
		name: "Prowler",
		short: "PR",
		accepts: ".csv,text/csv",
		accent: "#ff8a3d",
		description: "Cloud posture & compliance"
	},
	zap: {
		name: "OWASP ZAP",
		short: "ZP",
		accepts: ".json,application/json",
		accent: "#7c6cff",
		description: "Web application security"
	},
	trivy: {
		name: "Trivy",
		short: "TV",
		accepts: ".json,application/json",
		accent: "#16b8a6",
		description: "Images, code & infrastructure"
	}
};
var severityOrder = [
	"critical",
	"high",
	"medium",
	"low",
	"info"
];
var severityRank = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4
};
var severityLabel = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info"
};
function normalizeSeverity(value) {
	const text = String(value ?? "").toLowerCase().trim();
	if (text.includes("critical") || text === "4") return "critical";
	if (text.includes("high") || text === "3") return "high";
	if (text.includes("medium") || text.includes("moderate") || text === "2") return "medium";
	if (text.includes("low") || text === "1") return "low";
	return "info";
}
function valueAt(record, aliases) {
	const normalized = Object.fromEntries(Object.entries(record).map(([key, value]) => [key.toLowerCase().replace(/[ _-]/g, ""), value]));
	for (const alias of aliases) {
		const value = normalized[alias.toLowerCase().replace(/[ _-]/g, "")];
		if (value !== void 0 && value !== null && value !== "") return value;
	}
	return "";
}
function parseCsv(text) {
	const rows = [];
	let row = [], cell = "", quoted = false;
	const input = text.replace(/^\uFEFF/, "");
	const delimiterCounts = {
		",": 0,
		";": 0,
		"	": 0
	};
	let headerQuoted = false;
	for (let i = 0; i < input.length; i++) {
		const char = input[i];
		if (char === "\"" && input[i + 1] === "\"" && headerQuoted) {
			i++;
			continue;
		}
		if (char === "\"") {
			headerQuoted = !headerQuoted;
			continue;
		}
		if (!headerQuoted && char === "\n") break;
		if (!headerQuoted && char in delimiterCounts) delimiterCounts[char]++;
	}
	const knownHeaders = new Set([
		"checkid",
		"findinguid",
		"resourceuid",
		"status",
		"findingstatus",
		"severity",
		"requirementsid",
		"servicename",
		"checktitle",
		"resourcename",
		"region"
	]);
	const firstLine = input.split(/\r?\n/, 1)[0] ?? "";
	const delimiter = Object.keys(delimiterCounts).sort((a, b) => {
		const score = (candidate) => firstLine.split(candidate).map((header) => header.replace(/^\s*"|"\s*$/g, "").trim().toLowerCase().replace(/[ _-]/g, "")).filter((header) => knownHeaders.has(header)).length * 1e3 + delimiterCounts[candidate];
		return score(b) - score(a);
	})[0] || ",";
	for (let i = 0; i < input.length; i++) {
		const char = input[i];
		if (quoted) if (char === "\"" && input[i + 1] === "\"") {
			cell += "\"";
			i++;
		} else if (char === "\"") quoted = false;
		else cell += char;
		else if (char === "\"") quoted = true;
		else if (char === delimiter) {
			row.push(cell);
			cell = "";
		} else if (char === "\n") {
			row.push(cell.replace(/\r$/, ""));
			rows.push(row);
			row = [];
			cell = "";
		} else cell += char;
	}
	if (cell.length || row.length) {
		row.push(cell.replace(/\r$/, ""));
		rows.push(row);
	}
	if (quoted) throw new Error("The CSV contains an unclosed quoted field.");
	const nonEmpty = rows.filter((r) => r.some((v) => v.trim()));
	if (nonEmpty.length < 2) throw new Error("The Prowler CSV has no finding rows.");
	const headers = nonEmpty[0].map((h) => h.trim());
	return nonEmpty.slice(1).map((values) => Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])));
}
function parseDamagedProwlerCsv(text) {
	const physicalLines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
	const cleanLine = (line) => line.replace(/,{2,}\s*$/, "");
	const headers = cleanLine(physicalLines.shift() ?? "").split(";").map((header) => header.trim().replace(/^"|"$/g, ""));
	const normalizedHeaders = headers.map((header) => header.toLowerCase().replace(/[ _-]/g, ""));
	if (!normalizedHeaders.includes("checkid") || !normalizedHeaders.includes("status") || !normalizedHeaders.includes("timestamp")) return [];
	const recordStart = /^[^;\r\n]+;\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?;/;
	const blocks = [];
	let current = "";
	for (const sourceLine of physicalLines) {
		const line = cleanLine(sourceLine);
		if (recordStart.test(line)) {
			if (current) blocks.push(current);
			current = line;
		} else if (current) current += `\n${line}`;
	}
	if (current) blocks.push(current);
	const cleanValue = (value) => value.trim().replace(/^"+|"+$/g, "").replace(/""/g, "\"");
	return blocks.map((block) => {
		const values = block.split(";");
		const row = {};
		const reliableColumns = Math.min(headers.length, 31);
		for (let index = 0; index < reliableColumns; index++) row[headers[index]] = cleanValue(values[index] ?? "");
		return row;
	}).filter((row) => valueAt(row, ["check_id", "finding_uid"]) && valueAt(row, ["status"]));
}
function normalizeProwlerRows(rows) {
	return rows.map((raw, index) => {
		const checkId = String(valueAt(raw, [
			"check_id",
			"checkid",
			"finding_uid",
			"findinguid"
		]) || `row-${index + 1}`);
		const status = String(valueAt(raw, [
			"status",
			"finding_status",
			"findingstatus"
		]) || "UNKNOWN").toUpperCase();
		const service = String(valueAt(raw, [
			"service_name",
			"servicename",
			"service"
		]) || "Unspecified service");
		const resource = String(valueAt(raw, [
			"resource_name",
			"resourcename",
			"resource_uid",
			"resourceuid",
			"resource_arn",
			"resourcearn"
		]) || "No resource supplied");
		return {
			id: checkId,
			title: String(valueAt(raw, [
				"check_title",
				"checktitle",
				"finding_title",
				"findingtitle",
				"title"
			]) || checkId),
			severity: normalizeSeverity(valueAt(raw, ["severity", "risk"])),
			status,
			asset: resource,
			location: String(valueAt(raw, [
				"region",
				"location",
				"account_name",
				"accountname"
			]) || "Global"),
			category: service,
			detail: String(valueAt(raw, [
				"status_extended",
				"statusextended",
				"description"
			]) || "No detail supplied"),
			recommendation: String(valueAt(raw, [
				"remediation_recommendation_text",
				"remediationrecommendationtext",
				"remediation",
				"recommendation"
			]) || "Review the Prowler remediation guidance."),
			references: String(valueAt(raw, [
				"remediation_recommendation_url",
				"remediationrecommendationurl",
				"references"
			]) || "").split(/[|,]/).filter(Boolean),
			raw
		};
	});
}
function deduplicateProwlerFindings(findings) {
	const groups = /* @__PURE__ */ new Map();
	findings.forEach((finding) => {
		const account = String(valueAt(finding.raw, [
			"account_uid",
			"accountuid",
			"account_name",
			"accountname"
		]));
		const resource = String(valueAt(finding.raw, [
			"resource_uid",
			"resourceuid",
			"resource_arn",
			"resourcearn"
		]) || valueAt(finding.raw, ["finding_uid", "findinguid"]) || finding.asset);
		const timestamp = String(valueAt(finding.raw, ["timestamp"]));
		const key = `${account}\u0000${finding.id}\u0000${resource}`;
		const existing = groups.get(key);
		if (!existing) {
			groups.set(key, {
				finding,
				timestamp,
				timestamps: new Set(timestamp ? [timestamp] : []),
				occurrences: 1
			});
			return;
		}
		existing.occurrences++;
		if (timestamp) existing.timestamps.add(timestamp);
		if (timestamp >= existing.timestamp) {
			existing.finding = finding;
			existing.timestamp = timestamp;
		}
	});
	return Array.from(groups.values(), ({ finding, timestamps, occurrences }) => ({
		...finding,
		raw: {
			...finding.raw,
			scan_occurrences: occurrences,
			scan_timestamps: Array.from(timestamps).sort().join(" | ")
		}
	}));
}
function parseProwler(text) {
	let rows;
	let recovered = false;
	try {
		rows = parseCsv(text);
	} catch {
		rows = parseDamagedProwlerCsv(text);
		recovered = rows.length > 0;
	}
	const columns = Object.keys(rows[0] ?? {}).map((key) => key.toLowerCase().replace(/[ _-]/g, ""));
	const hasIdentity = columns.some((key) => [
		"checkid",
		"findinguid",
		"resourceuid"
	].includes(key));
	const hasStatus = columns.some((key) => ["status", "findingstatus"].includes(key));
	const recognizedStatuses = rows.filter((row) => [
		"PASS",
		"FAIL",
		"MANUAL",
		"MUTED"
	].includes(String(valueAt(row, [
		"status",
		"finding_status",
		"findingstatus"
	])).toUpperCase())).length;
	const implausibleRows = rows.length > 0 && recognizedStatuses / rows.length < .5;
	if (!hasIdentity || !hasStatus || implausibleRows) {
		const recoveredRows = parseDamagedProwlerCsv(text);
		if (recoveredRows.length) {
			rows = recoveredRows;
			recovered = true;
		} else throw new Error("This CSV does not match a Prowler export. A check/finding ID and status column are required.");
	}
	const findings = deduplicateProwlerFindings(normalizeProwlerRows(rows));
	const scanRuns = new Set(rows.map((row) => String(valueAt(row, ["timestamp"]))).filter(Boolean)).size;
	return {
		fileName: "",
		importedAt: (/* @__PURE__ */ new Date()).toISOString(),
		findings,
		meta: {
			"scan rows": rows.length,
			"scan runs": scanRuns || 1,
			"unique findings": findings.length,
			failed: findings.filter((finding) => finding.status === "FAIL").length,
			passed: findings.filter((finding) => finding.status === "PASS").length,
			...recovered ? { format: "Recovered Prowler CSV" } : {}
		}
	};
}
function frameworkNameFromFile(fileName, row) {
	const cisVersion = fileName.match(/_cis_([\d.]+)_azure/i)?.[1];
	if (cisVersion) return `CIS Azure ${cisVersion}`;
	const base = fileName.replace(/\.csv$/i, "").replace(/^nava-scan-full-jul\d+_/i, "").replace(/_azure$/i, "");
	return {
		"c5": "C5",
		"ccc": "CCC",
		"cis_controls_8.1": "CIS Controls 8.1",
		"csa_ccm_4.0": "CSA CCM 4.0",
		"dora_2022_2554": "DORA 2022/2554",
		"ens_rd2022": "ENS RD2022",
		"fedramp_20x_ksi_low": "FedRAMP 20x KSI Low",
		"hipaa": "HIPAA",
		"iso27001_2022": "ISO 27001:2022",
		"mitre_attack": "MITRE ATT&CK",
		"nis2": "NIS2",
		"pci_4.0": "PCI DSS 4.0",
		"prowler_threatscore": "Prowler ThreatScore",
		"rbi_cyber_security_framework": "RBI Cyber Security Framework",
		"secnumcloud_3.2": "SecNumCloud 3.2",
		"soc2": "SOC 2"
	}[base.toLowerCase()] ?? String(valueAt(row, ["framework"]) || base.replace(/_/g, " ").toUpperCase());
}
function parseProwlerCompliance(text, fileName) {
	const rows = parseCsv(text);
	const columns = Object.keys(rows[0] ?? {}).map((key) => key.toLowerCase().replace(/[ _-]/g, ""));
	if (!columns.includes("requirementsid") || !columns.includes("status")) throw new Error("This is not a Prowler compliance CSV.");
	const statuses = {
		pass: 0,
		fail: 0,
		manual: 0
	};
	const requirements = /* @__PURE__ */ new Set();
	const checks = /* @__PURE__ */ new Set();
	rows.forEach((row) => {
		const status = String(valueAt(row, ["status"])).toUpperCase();
		if (status === "PASS") statuses.pass++;
		else if (status === "FAIL") statuses.fail++;
		else if (status === "MANUAL") statuses.manual++;
		const requirement = String(valueAt(row, ["requirements_id", "requirementsid"]));
		const check = String(valueAt(row, ["checkid", "check_id"]));
		if (requirement) requirements.add(requirement);
		if (check) checks.add(check);
	});
	const automated = statuses.pass + statuses.fail;
	return {
		fileName,
		framework: frameworkNameFromFile(fileName, rows[0]),
		total: rows.length,
		pass: statuses.pass,
		fail: statuses.fail,
		manual: statuses.manual,
		requirements: requirements.size,
		checks: checks.size,
		passRate: automated ? Math.round(statuses.pass / automated * 1e3) / 10 : 0
	};
}
function parseZap(payload) {
	if (!payload || typeof payload !== "object") throw new Error("The ZAP JSON root must be an object.");
	const root = payload;
	const sites = Array.isArray(root.site) ? root.site : Array.isArray(root.sites) ? root.sites : [];
	if (!sites.length) throw new Error("No ZAP sites were found. Expected a JSON report with a site array.");
	const findings = [];
	let instanceCount = 0;
	let alertCount = 0;
	sites.forEach((siteValue, siteIndex) => {
		const site = siteValue ?? {};
		(Array.isArray(site.alerts) ? site.alerts : []).forEach((alertValue, alertIndex) => {
			alertCount++;
			const alert = alertValue ?? {};
			const instances = Array.isArray(alert.instances) ? alert.instances : [];
			instanceCount += instances.length;
			(instances.length ? instances : [{}]).forEach((instanceValue, instanceIndex) => {
				const instance = instanceValue ?? {};
				const evidence = [
					instance.method,
					instance.param && `parameter: ${instance.param}`,
					instance.evidence && `evidence: ${instance.evidence}`
				].filter(Boolean).join(" · ");
				findings.push({
					id: String(alert.pluginid ?? alert.alertRef ?? `${siteIndex}-${alertIndex}`),
					title: String(alert.alert ?? alert.name ?? "Untitled ZAP alert"),
					severity: normalizeSeverity(alert.riskcode ?? alert.riskdesc),
					status: String(alert.confidence ?? "Reported"),
					asset: String(site["@name"] ?? site.name ?? instance.uri ?? "Unknown site"),
					location: String(instance.uri ?? site["@host"] ?? site.host ?? "Unknown URL"),
					category: String(alert.cweid ? `CWE-${alert.cweid}` : alert.wascid ? `WASC-${alert.wascid}` : "Web security"),
					detail: `${String(alert.desc ?? alert.description ?? "No description supplied")}${evidence ? `\n\nEndpoint: ${evidence}` : ""}`,
					recommendation: String(alert.solution ?? "Review and remediate the affected endpoint."),
					references: String(alert.reference ?? "").split(/\s+/).filter((v) => v.startsWith("http")),
					raw: {
						...alert,
						_instance: instance,
						_instanceIndex: instanceIndex
					}
				});
			});
		});
	});
	return {
		fileName: "",
		importedAt: (/* @__PURE__ */ new Date()).toISOString(),
		findings,
		meta: {
			sites: sites.length,
			alerts: alertCount,
			instances: instanceCount
		}
	};
}
function parseTrivy(payload) {
	if (!payload || typeof payload !== "object") throw new Error("The Trivy JSON root must be an object.");
	const root = payload;
	const hasResults = Array.isArray(root.Results) || Array.isArray(root.results);
	const results = Array.isArray(root.Results) ? root.Results : Array.isArray(root.results) ? root.results : [];
	if (!hasResults) throw new Error("No Trivy Results array was found in this report.");
	const findings = [];
	results.forEach((resultValue, resultIndex) => {
		const result = resultValue ?? {};
		const target = String(result.Target ?? result.target ?? "Unknown target");
		const source = String(result.Class ?? result.Type ?? "Trivy");
		[
			["Vulnerability", Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : []],
			["Misconfiguration", Array.isArray(result.Misconfigurations) ? result.Misconfigurations : []],
			["Secret", Array.isArray(result.Secrets) ? result.Secrets : []],
			["License", Array.isArray(result.Licenses) ? result.Licenses : []]
		].forEach(([kind, entries]) => entries.forEach((entryValue, entryIndex) => {
			const entry = entryValue ?? {};
			const primary = String(entry.VulnerabilityID ?? entry.ID ?? entry.RuleID ?? entry.Name ?? `${resultIndex}-${kind}-${entryIndex}`);
			const pkg = String(entry.PkgName ?? entry.Package ?? entry.Name ?? "");
			findings.push({
				id: primary,
				title: String(entry.Title ?? entry.Message ?? entry.Name ?? primary),
				severity: normalizeSeverity(entry.Severity),
				status: String(entry.Status ?? (entry.FixedVersion ? "Fix available" : "Detected")),
				asset: target,
				location: String(entry.PkgPath ?? entry.FilePath ?? entry.PrimaryURL ?? (pkg || target)),
				category: `${kind}${source ? ` · ${source}` : ""}`,
				detail: String(entry.Description ?? entry.Message ?? (pkg ? `${pkg} ${entry.InstalledVersion ?? ""}` : "No description supplied")),
				recommendation: String(entry.Resolution ?? (entry.FixedVersion ? `Upgrade to ${entry.FixedVersion}` : entry.Recommendation ?? "Review the Trivy finding and apply the recommended fix.")),
				references: [entry.PrimaryURL, ...Array.isArray(entry.References) ? entry.References : []].filter(Boolean).map(String),
				raw: entry
			});
		}));
	});
	return {
		fileName: "",
		importedAt: (/* @__PURE__ */ new Date()).toISOString(),
		findings,
		meta: {
			targets: results.length,
			findings: findings.length,
			artifact: String(root.ArtifactName ?? root.ArtifactType ?? "Trivy report")
		}
	};
}
function formatDate(value) {
	return new Intl.DateTimeFormat("en", {
		dateStyle: "medium",
		timeStyle: "short"
	}).format(new Date(value));
}
function AppIcon({ name }) {
	const glyph = {
		grid: "▦",
		upload: "↥",
		search: "⌕",
		shield: "◇",
		file: "▤",
		chevron: "›",
		check: "✓"
	}[name];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: "glyph",
		"aria-hidden": "true",
		children: glyph
	});
}
function Home() {
	const [active, setActive] = (0, import_react.useState)("prowler");
	const [data, setData] = (0, import_react.useState)({});
	const [error, setError] = (0, import_react.useState)("");
	const [query, setQuery] = (0, import_react.useState)("");
	const [severity, setSeverity] = (0, import_react.useState)("all");
	const [resultStatus, setResultStatus] = (0, import_react.useState)("all");
	const [prowlerView, setProwlerView] = (0, import_react.useState)("findings");
	const [inventoryMode, setInventoryMode] = (0, import_react.useState)("issues");
	const [serviceFilter, setServiceFilter] = (0, import_react.useState)("all");
	const [regionFilter, setRegionFilter] = (0, import_react.useState)("all");
	const [selectedGroup, setSelectedGroup] = (0, import_react.useState)(null);
	const [selected, setSelected] = (0, import_react.useState)(null);
	const [dragging, setDragging] = (0, import_react.useState)(false);
	const [copilotOpen, setCopilotOpen] = (0, import_react.useState)(false);
	const [copilotConfigured, setCopilotConfigured] = (0, import_react.useState)(null);
	const [copilotModel, setCopilotModel] = (0, import_react.useState)("gpt-5.4-mini");
	const [copilotInput, setCopilotInput] = (0, import_react.useState)("");
	const [copilotBusy, setCopilotBusy] = (0, import_react.useState)(false);
	const [copilotMessages, setCopilotMessages] = (0, import_react.useState)([{
		role: "assistant",
		text: "Import a scan, then ask me to prioritize risks, explain a finding, or create a remediation plan."
	}]);
	const inputRef = (0, import_react.useRef)(null);
	const folderRef = (0, import_react.useRef)(null);
	const current = data[active];
	const statusFindings = (0, import_react.useMemo)(() => {
		if (!current) return [];
		if (active !== "prowler" || resultStatus === "all") return current.findings;
		return current.findings.filter((finding) => finding.status === resultStatus);
	}, [
		active,
		current,
		resultStatus
	]);
	const visible = (0, import_react.useMemo)(() => {
		if (!current) return [];
		const term = query.toLowerCase().trim();
		return statusFindings.filter((finding) => (severity === "all" || finding.severity === severity) && (serviceFilter === "all" || finding.category === serviceFilter) && (regionFilter === "all" || finding.location === regionFilter) && (!term || [
			finding.id,
			finding.title,
			finding.asset,
			finding.location,
			finding.category,
			finding.status
		].join(" ").toLowerCase().includes(term)));
	}, [
		current,
		query,
		severity,
		serviceFilter,
		regionFilter,
		statusFindings
	]);
	const findingGroups = (0, import_react.useMemo)(() => {
		const groups = /* @__PURE__ */ new Map();
		visible.forEach((finding) => {
			const key = `${finding.id}|${finding.title}`;
			groups.set(key, [...groups.get(key) ?? [], finding]);
		});
		return Array.from(groups, ([key, findings]) => {
			const first = findings[0];
			return {
				key,
				id: first.id,
				title: first.title,
				severity: findings.reduce((highest, finding) => severityRank[finding.severity] < severityRank[highest] ? finding.severity : highest, first.severity),
				category: first.category,
				findings,
				resources: new Set(findings.map((finding) => finding.asset)).size,
				fail: findings.filter((finding) => finding.status === "FAIL").length,
				pass: findings.filter((finding) => finding.status === "PASS").length
			};
		}).sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || b.fail - a.fail || b.resources - a.resources);
	}, [visible]);
	const serviceOptions = (0, import_react.useMemo)(() => Array.from(new Set(statusFindings.map((finding) => finding.category).filter(Boolean))).sort(), [statusFindings]);
	const regionOptions = (0, import_react.useMemo)(() => Array.from(new Set(statusFindings.map((finding) => finding.location).filter(Boolean))).sort(), [statusFindings]);
	const relatedFindings = (0, import_react.useMemo)(() => selected && current ? current.findings.filter((finding) => finding.asset === selected.asset && !(finding.id === selected.id && finding.title === selected.title)).slice(0, 12) : [], [current, selected]);
	const counts = (0, import_react.useMemo)(() => Object.fromEntries(severityOrder.map((level) => [level, statusFindings.filter((f) => f.severity === level).length])), [statusFindings]);
	const prowlerStatusCounts = (0, import_react.useMemo)(() => ({
		fail: current?.findings.filter((finding) => finding.status === "FAIL").length ?? 0,
		pass: current?.findings.filter((finding) => finding.status === "PASS").length ?? 0
	}), [current]);
	const complianceTotals = (0, import_react.useMemo)(() => {
		const items = current?.compliance ?? [];
		const totals = items.reduce((sum, item) => ({
			total: sum.total + item.total,
			pass: sum.pass + item.pass,
			fail: sum.fail + item.fail,
			manual: sum.manual + item.manual
		}), {
			total: 0,
			pass: 0,
			fail: 0,
			manual: 0
		});
		const automated = totals.pass + totals.fail;
		return {
			...totals,
			frameworks: items.length,
			passRate: automated ? Math.round(totals.pass / automated * 1e3) / 10 : 0
		};
	}, [current]);
	async function importFiles(selectedFiles) {
		setError("");
		setSelected(null);
		setSelectedGroup(null);
		setQuery("");
		setSeverity("all");
		setResultStatus("all");
		setServiceFilter("all");
		setRegionFilter("all");
		try {
			const files = active === "zap" ? selectedFiles.filter((file) => file.name.toLowerCase().endsWith(".json")) : active === "prowler" ? selectedFiles.filter((file) => file.name.toLowerCase().endsWith(".csv")) : selectedFiles.slice(0, 1);
			if (!files.length) throw new Error(active === "zap" ? "No JSON reports were found in this selection." : "No report was selected.");
			const reports = [];
			const compliance = [];
			for (const file of files) {
				const text = await file.text();
				let parsed;
				if (active === "prowler") {
					if (text.slice(0, text.indexOf("\n") === -1 ? 4e3 : text.indexOf("\n")).toLowerCase().replace(/[ _-]/g, "").includes("requirementsid")) {
						compliance.push(parseProwlerCompliance(text, file.name));
						continue;
					}
					parsed = parseProwler(text);
				} else {
					let json;
					try {
						json = JSON.parse(text.replace(/^\uFEFF/, ""));
					} catch {
						throw new Error(`${file.name} is not valid JSON.`);
					}
					try {
						parsed = active === "zap" ? parseZap(json) : parseTrivy(json);
					} catch (reason) {
						throw new Error(`${file.name}: ${reason instanceof Error ? reason.message : "The report could not be read."}`);
					}
				}
				parsed.fileName = file.name;
				reports.push(parsed);
			}
			let parsed;
			if (active === "prowler") {
				const core = reports.flatMap((report) => report.findings);
				const selectedCount = selectedFiles.length;
				parsed = {
					fileName: selectedCount > 1 ? `${selectedCount} Prowler export files` : reports[0]?.fileName ?? `${compliance.length} compliance reports`,
					importedAt: (/* @__PURE__ */ new Date()).toISOString(),
					findings: core,
					compliance: compliance.sort((a, b) => a.framework.localeCompare(b.framework)),
					meta: {
						files: selectedCount,
						findings: core.length,
						frameworks: compliance.length,
						"compliance rows": compliance.reduce((sum, item) => sum + item.total, 0)
					}
				};
			} else if (active === "zap" && reports.length > 1) parsed = {
				fileName: `${reports.length} ZAP endpoint reports`,
				importedAt: (/* @__PURE__ */ new Date()).toISOString(),
				findings: reports.flatMap((report) => report.findings),
				meta: {
					files: reports.length,
					sites: reports.reduce((sum, report) => sum + Number(report.meta.sites ?? 0), 0),
					alerts: reports.reduce((sum, report) => sum + Number(report.meta.alerts ?? 0), 0),
					instances: reports.reduce((sum, report) => sum + Number(report.meta.instances ?? 0), 0)
				}
			};
			else parsed = reports[0];
			setData((previous) => ({
				...previous,
				[active]: parsed
			}));
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The file could not be read.");
		}
	}
	function onFileChange(event) {
		const files = Array.from(event.target.files ?? []);
		if (files.length) importFiles(files);
		event.target.value = "";
	}
	function onDrop(event) {
		event.preventDefault();
		setDragging(false);
		const files = Array.from(event.dataTransfer.files ?? []);
		if (files.length) importFiles(files);
	}
	function exportVisible() {
		const headers = [
			"id",
			"title",
			"severity",
			"status",
			"asset",
			"location",
			"category",
			"detail",
			"recommendation"
		];
		const escape = (value) => `"${value.replace(/"/g, "\"\"")}"`;
		const csv = [headers.join(","), ...visible.map((f) => headers.map((key) => escape(String(f[key] ?? ""))).join(","))].join("\n");
		const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
		const anchor = document.createElement("a");
		anchor.href = url;
		anchor.download = `${active}-filtered-findings.csv`;
		anchor.click();
		URL.revokeObjectURL(url);
	}
	async function openCopilot() {
		setCopilotOpen(true);
		if (copilotConfigured !== null) return;
		try {
			const config = await (await fetch("/api/security-chat")).json();
			setCopilotConfigured(Boolean(config.configured));
			if (config.model) setCopilotModel(config.model);
		} catch {
			setCopilotConfigured(false);
		}
	}
	async function sendCopilot(question) {
		const trimmed = question.trim();
		if (!trimmed || copilotBusy) return;
		if (!current) {
			setCopilotMessages((messages) => [...messages, {
				role: "assistant",
				text: "Import a Prowler, ZAP, or Trivy report first so I have evidence to analyze."
			}]);
			return;
		}
		if (!copilotConfigured) return;
		const priority = Object.fromEntries(severityOrder.map((level, index) => [level, index]));
		const candidates = current.findings.filter((finding) => active !== "prowler" || finding.status === "FAIL").sort((a, b) => priority[a.severity] - priority[b.severity]).slice(0, 50).map(({ id, title, severity: findingSeverity, status, asset, location, category, detail, recommendation }) => ({
			id,
			title,
			severity: findingSeverity,
			status,
			asset,
			location,
			category,
			detail,
			recommendation
		}));
		if (!candidates.length) {
			setCopilotMessages((messages) => [...messages, {
				role: "assistant",
				text: "This report has no actionable failed or detected findings to analyze."
			}]);
			return;
		}
		setCopilotMessages((messages) => [...messages, {
			role: "user",
			text: trimmed
		}]);
		setCopilotInput("");
		setCopilotBusy(true);
		try {
			const response = await fetch("/api/security-chat", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					question: trimmed,
					scanner: scannerMeta[active].name,
					findings: candidates
				})
			});
			const result = await response.json();
			if (!response.ok || !result.answer) throw new Error(result.error || "Security Copilot could not complete the analysis.");
			if (result.model) setCopilotModel(result.model);
			setCopilotMessages((messages) => [...messages, {
				role: "assistant",
				text: result.answer
			}]);
		} catch (reason) {
			setCopilotMessages((messages) => [...messages, {
				role: "assistant",
				text: reason instanceof Error ? reason.message : "Security Copilot could not complete the analysis."
			}]);
		} finally {
			setCopilotBusy(false);
		}
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
			className: "topbar",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "brand",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "brandMark",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "shield" })
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: ["Sentinel", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "brandAccent",
						children: "Scope"
					})] })]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "workspace",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "workspaceDot" }),
						" Security workspace ",
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "workspaceArrow",
							children: "⌄"
						})
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "topActions",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "privacy",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "privacyDot" }), " Local processing only"]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
						className: "copilotButton",
						onClick: () => void openCopilot(),
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "✦" }), " Security Copilot"]
					})]
				})
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "shell",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
				className: "sidebar",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "sideLabel",
						children: "SCANNERS"
					}),
					[
						"prowler",
						"zap",
						"trivy"
					].map((scanner) => {
						const meta = scannerMeta[scanner];
						return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							className: `sideItem ${active === scanner ? "active" : ""}`,
							onClick: () => {
								setActive(scanner);
								setError("");
								setQuery("");
								setSeverity("all");
								setResultStatus("all");
								setServiceFilter("all");
								setRegionFilter("all");
								setProwlerView("findings");
								setSelected(null);
								setSelectedGroup(null);
							},
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
									className: "scannerIcon",
									style: { "--accent": meta.accent },
									children: meta.short
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: meta.name }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: meta.description })] }),
								data[scanner] && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
									className: "loaded",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "check" })
								})
							]
						}, scanner);
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "sideFoot",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "shield" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Your data stays here" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Files are parsed in your browser and are never uploaded." })] })]
					})
				]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "content",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "pageHead",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "eyebrow",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { style: { background: scannerMeta[active].accent } }),
									" ",
									active === "prowler" && prowlerView === "compliance" ? "Cloud compliance & control mappings" : scannerMeta[active].description
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", { children: active === "prowler" && prowlerView === "compliance" ? "Prowler compliance" : `${scannerMeta[active].name} findings` }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: active === "prowler" && prowlerView === "compliance" ? "Compare framework pass rates, failures, manual reviews, requirements, and mapped checks." : "Import, inspect, filter, and export every finding from your scan report." })
						] }), current && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							className: "secondaryButton",
							onClick: () => inputRef.current?.click(),
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "upload" }), " Replace report"]
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("nav", {
						className: "tabs",
						"aria-label": "Scanner report tabs",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								className: active === "prowler" && prowlerView === "findings" ? "active" : "",
								onClick: () => {
									setActive("prowler");
									setProwlerView("findings");
									setError("");
									setSeverity("all");
									setResultStatus("all");
									setServiceFilter("all");
									setRegionFilter("all");
									setSelected(null);
									setSelectedGroup(null);
								},
								children: ["Prowler", data.prowler && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: data.prowler.findings.length })]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								className: active === "prowler" && prowlerView === "compliance" ? "active" : "",
								onClick: () => {
									setActive("prowler");
									setProwlerView("compliance");
									setError("");
									setSeverity("all");
									setResultStatus("all");
									setServiceFilter("all");
									setRegionFilter("all");
									setSelected(null);
									setSelectedGroup(null);
								},
								children: ["Compliance", data.prowler?.compliance?.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: data.prowler.compliance.length }) : null]
							}),
							["zap", "trivy"].map((scanner) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								className: active === scanner ? "active" : "",
								onClick: () => {
									setActive(scanner);
									setError("");
									setSeverity("all");
									setResultStatus("all");
									setServiceFilter("all");
									setRegionFilter("all");
									setProwlerView("findings");
									setSelected(null);
									setSelectedGroup(null);
								},
								children: [scannerMeta[scanner].name, data[scanner] && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: data[scanner].findings.length })]
							}, scanner))
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						ref: inputRef,
						className: "hiddenInput",
						type: "file",
						accept: scannerMeta[active].accepts,
						multiple: active === "zap" || active === "prowler",
						onChange: onFileChange
					}),
					(active === "zap" || active === "prowler") && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						ref: folderRef,
						className: "hiddenInput",
						type: "file",
						accept: active === "zap" ? ".json,application/json" : ".csv,text/csv",
						multiple: true,
						onChange: onFileChange,
						webkitdirectory: "",
						directory: ""
					}),
					!current ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
						className: `uploadCard ${dragging ? "dragging" : ""}`,
						onDragOver: (e) => {
							e.preventDefault();
							setDragging(true);
						},
						onDragLeave: () => setDragging(false),
						onDrop,
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "uploadVisual",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
									className: "fileSheet",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "file" })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
									className: "uploadArrow",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "upload" })
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: active === "zap" ? "Import all ZAP endpoint reports" : active === "prowler" ? "Import the complete Prowler export" : `Drop your ${scannerMeta[active].name} report here` }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: active === "prowler" ? "Select the core CSV and compliance CSVs together, or choose the entire export folder." : active === "zap" ? "Select every JSON report at once, choose the whole folder, or drop the files here." : `Choose a JSON report exported by ${scannerMeta[active].name}.` }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "uploadActions",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									className: "primaryButton",
									style: { "--accent": scannerMeta[active].accent },
									onClick: () => inputRef.current?.click(),
									children: active === "zap" ? "Choose JSON reports" : active === "prowler" ? "Choose CSV reports" : "Choose report"
								}), (active === "zap" || active === "prowler") && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
									className: "secondaryButton",
									onClick: () => folderRef.current?.click(),
									children: "Choose folder"
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "supported",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "SUPPORTED" }), active === "prowler" ? "CSV · Comma or semicolon · Multiline quoted fields" : "JSON · Standard report schema"]
							}),
							error && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "errorBox",
								role: "alert",
								children: error
							})
						]
					}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
						error && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "errorBox topError",
							role: "alert",
							children: error
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
							className: "reportMeta",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "fileBadge",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "file" })
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: current.fileName }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("small", { children: [
								"Imported ",
								formatDate(current.importedAt),
								" · ",
								current.findings.length.toLocaleString(),
								" unique findings",
								active === "prowler" ? " (latest result per check and full resource ID)" : ""
							] })] })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "metaStats",
								children: Object.entries(current.meta).slice(0, 4).map(([key, value]) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: key }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: String(value) })] }, key))
							})]
						}),
						active === "prowler" && prowlerView === "compliance" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
							className: "complianceHero",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "FRAMEWORKS" }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: complianceTotals.frameworks }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Imported compliance standards" })
								] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "AUTOMATED PASS RATE" }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [complianceTotals.passRate, "%"] }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "complianceMeter",
										children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", { style: { width: `${complianceTotals.passRate}%` } })
									})
								] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "complianceStatus pass",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "PASS ROWS" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: complianceTotals.pass.toLocaleString() })]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "complianceStatus fail",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "FAIL ROWS" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: complianceTotals.fail.toLocaleString() })]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "complianceStatus manual",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "MANUAL ROWS" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: complianceTotals.manual.toLocaleString() })]
								})
							]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
							className: "findingsPanel compliancePanel",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "panelHead",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: "Compliance framework inventory" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
									complianceTotals.total.toLocaleString(),
									" mapped control results across ",
									complianceTotals.frameworks,
									" frameworks; repeated mappings are intentionally kept within each framework."
								] })] })
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "tableWrap",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
									className: "complianceTable",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Framework" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Automated pass rate" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Pass" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Fail" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Manual" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Requirements" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Checks" })
									] }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", { children: current.compliance.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: item.framework }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: item.fileName })] }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "rateCell",
											children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [item.passRate, "%"] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("b", { style: { width: `${item.passRate}%` } }) })]
										}) }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "countPass",
											children: item.pass.toLocaleString()
										}) }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "countFail",
											children: item.fail.toLocaleString()
										}) }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: item.manual.toLocaleString() }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: item.requirements.toLocaleString() }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: item.checks.toLocaleString() })
									] }, item.fileName)) })]
								})
							})]
						})] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
							active === "prowler" && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
								className: "resultSwitch",
								"aria-label": "Prowler result category",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Result category" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Review failed and passed checks separately" })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "resultOptions",
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
											className: resultStatus === "all" ? "active all" : "all",
											onClick: () => {
												setResultStatus("all");
												setSeverity("all");
											},
											children: ["All checks ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: current.findings.length })]
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
											className: resultStatus === "FAIL" ? "active fail" : "fail",
											onClick: () => {
												setResultStatus("FAIL");
												setSeverity("all");
											},
											children: ["Failed ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: prowlerStatusCounts.fail })]
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
											className: resultStatus === "PASS" ? "active pass" : "pass",
											onClick: () => {
												setResultStatus("PASS");
												setSeverity("all");
											},
											children: ["Passed ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: prowlerStatusCounts.pass })]
										})
									]
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
								className: "summaryGrid",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
									className: "totalCard",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: active === "prowler" && resultStatus !== "all" ? `${resultStatus} CHECKS` : "TOTAL FINDINGS" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: statusFindings.length.toLocaleString() }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: visible.length === statusFindings.length ? resultStatus === "all" ? "Across the complete report" : `of ${current.findings.length.toLocaleString()} total checks` : `${visible.length.toLocaleString()} match current filters` })
									] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "donut",
										style: { background: `conic-gradient(#ef4b5f 0 ${statusFindings.length ? counts.critical / statusFindings.length * 100 : 0}%, #ff8a3d 0 ${statusFindings.length ? (counts.critical + counts.high) / statusFindings.length * 100 : 0}%, #f5be3d 0 ${statusFindings.length ? (counts.critical + counts.high + counts.medium) / statusFindings.length * 100 : 0}%, #67b7a8 0 100%)` },
										children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [
											statusFindings.length ? Math.round((counts.critical + counts.high) / statusFindings.length * 100) : 0,
											"%",
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "urgent" })
										] })
									})]
								}), severityOrder.map((level) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
									className: `severityCard ${level} ${severity === level ? "selected" : ""}`,
									onClick: () => setSeverity(severity === level ? "all" : level),
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "severityLine" }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: severityLabel[level].toUpperCase() }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: counts[level].toLocaleString() }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
											className: "miniBar",
											children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("i", { style: { width: `${statusFindings.length ? Math.max(3, counts[level] / statusFindings.length * 100) : 0}%` } })
										})
									]
								}, level))]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
								className: "findingsPanel",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "panelHead",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: active === "prowler" && inventoryMode === "issues" ? "Issues grouped by check" : active === "prowler" && resultStatus !== "all" ? `${resultStatus === "FAIL" ? "Failed" : "Passed"} check inventory` : "Finding inventory" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: active === "prowler" && inventoryMode === "issues" ? `${findingGroups.length.toLocaleString()} issue types across ${visible.length.toLocaleString()} unique resource findings` : `Showing ${visible.length.toLocaleString()} of ${statusFindings.length.toLocaleString()} ${active === "prowler" ? "unique resource findings" : "findings"}` })] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "panelActions",
											children: [active === "prowler" && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "viewToggle",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
													className: inventoryMode === "issues" ? "active" : "",
													onClick: () => setInventoryMode("issues"),
													children: "Issues"
												}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
													className: inventoryMode === "resources" ? "active" : "",
													onClick: () => setInventoryMode("resources"),
													children: "All resources"
												})]
											}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
												className: "textButton",
												onClick: exportVisible,
												disabled: !visible.length,
												children: ["Export filtered CSV ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "chevron" })]
											})]
										})]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "toolbar",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
												className: "search",
												children: [
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "search" }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
														value: query,
														onChange: (e) => setQuery(e.target.value),
														placeholder: "Search ID, asset, finding or location…"
													}),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("kbd", { children: "⌘ K" })
												]
											}),
											active === "prowler" && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "facetFilters",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
													value: serviceFilter,
													onChange: (event) => setServiceFilter(event.target.value),
													"aria-label": "Filter by service",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
														value: "all",
														children: "All services"
													}), serviceOptions.map((service) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
														value: service,
														children: service
													}, service))]
												}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
													value: regionFilter,
													onChange: (event) => setRegionFilter(event.target.value),
													"aria-label": "Filter by region",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
														value: "all",
														children: "All regions"
													}), regionOptions.map((region) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
														value: region,
														children: region
													}, region))]
												})]
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "filterPills",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
													className: severity === "all" ? "active" : "",
													onClick: () => setSeverity("all"),
													children: "All"
												}), severityOrder.map((level) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
													className: severity === level ? "active" : "",
													onClick: () => setSeverity(level),
													children: [
														severityLabel[level],
														" ",
														/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: counts[level] })
													]
												}, level))]
											})
										]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "tableWrap",
										children: [active === "prowler" && inventoryMode === "issues" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
											className: "groupTable",
											children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Severity" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Issue / check" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Affected resources" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Service" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Results" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { "aria-label": "Open" })
											] }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", { children: findingGroups.map((group) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
												onClick: () => setSelectedGroup(group),
												tabIndex: 0,
												onKeyDown: (event) => {
													if (event.key === "Enter") setSelectedGroup(group);
												},
												children: [
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
														className: `severityBadge ${group.severity}`,
														children: severityLabel[group.severity]
													}) }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: group.title }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: group.id })] }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [group.resources.toLocaleString(), " resources"] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("small", { children: [group.findings.length.toLocaleString(), " unique findings"] })] }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: group.category }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
														className: "groupResult fail",
														children: [group.fail, " fail"]
													}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
														className: "groupResult pass",
														children: [group.pass, " pass"]
													})] }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "chevron" }) })
												]
											}, group.key)) })]
										}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Severity" }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Finding" }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Asset / target" }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Category" }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { children: "Status" }),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { "aria-label": "Open" })
										] }) }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", { children: visible.map((finding, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
											onClick: () => setSelected(finding),
											tabIndex: 0,
											onKeyDown: (e) => {
												if (e.key === "Enter") setSelected(finding);
											},
											children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: `severityBadge ${finding.severity}`,
													children: severityLabel[finding.severity]
												}) }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: finding.title }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: finding.id })] }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: finding.asset }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: finding.location })] }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: finding.category }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "statusBadge",
													children: finding.status
												}) }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "chevron" }) })
											]
										}, `${finding.id}-${index}`)) })] }), !visible.length && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "emptyState",
											children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "search" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "No findings match" }),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Clear the search or select another severity." })
											]
										})]
									})
								]
							})
						] })
					] })
				]
			})]
		}),
		copilotOpen && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "copilotBackdrop",
			onClick: () => setCopilotOpen(false),
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
				className: "copilotPanel",
				onClick: (e) => e.stopPropagation(),
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "copilotHead",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "copilotMark",
							children: "✦"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: "Security Copilot" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [copilotModel, " · analyzes only the context you send"] })] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							className: "close",
							onClick: () => setCopilotOpen(false),
							"aria-label": "Close Security Copilot",
							children: "×"
						})
					]
				}), copilotConfigured === false ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "copilotSetup",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "setupIcon",
							children: "⌁"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "Connect the OpenAI API" }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
							"Keep your key on the local server. Create ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", { children: ".env.local" }),
							", add ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", { children: "OPENAI_API_KEY=your_key" }),
							", then restart SentinelScope."
						] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
							href: "https://platform.openai.com/api-keys",
							target: "_blank",
							rel: "noreferrer",
							children: "Open API key settings ↗"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Do not paste your API key into this chat or the browser." })
					]
				}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "contextBar",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: current ? scannerMeta[active].name : "No report" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: current ? `Up to 50 highest-priority ${active === "prowler" ? "failed checks" : "findings"} will be sent with each question.` : "Import a report to provide analysis context." })]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "quickPrompts",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								disabled: !current || copilotBusy,
								onClick: () => void sendCopilot("Prioritize the most urgent issues and explain why they should be fixed first."),
								children: "Prioritize risks"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								disabled: !current || copilotBusy,
								onClick: () => void sendCopilot("Create a practical remediation plan grouped into quick wins, near-term work, and longer-term improvements."),
								children: "Build fix plan"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								disabled: !current || copilotBusy,
								onClick: () => void sendCopilot("Find the highest-impact quick wins and give exact validation steps after each fix."),
								children: "Find quick wins"
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "chatMessages",
						children: [copilotMessages.map((message, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: `chatMessage ${message.role}`,
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: message.role === "assistant" ? "✦" : "You" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: message.text })]
						}, index)), copilotBusy && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "chatMessage assistant thinking",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "✦" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Reviewing scanner evidence…" })]
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
						className: "chatComposer",
						onSubmit: (event) => {
							event.preventDefault();
							sendCopilot(copilotInput);
						},
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
							value: copilotInput,
							onChange: (event) => setCopilotInput(event.target.value),
							placeholder: "Ask how to fix an issue…",
							rows: 3,
							disabled: copilotBusy
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Only summarized finding fields are sent." }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "submit",
							disabled: !copilotInput.trim() || copilotBusy || !current,
							children: "Send ↗"
						})] })]
					})
				] })]
			})
		}),
		selectedGroup && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "drawerBackdrop",
			onClick: () => setSelectedGroup(null),
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
				className: "drawer groupDrawer",
				onClick: (event) => event.stopPropagation(),
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						className: "close",
						onClick: () => setSelectedGroup(null),
						"aria-label": "Close issue group",
						children: "×"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "drawerTop",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: `severityBadge ${selectedGroup.severity}`,
							children: severityLabel[selectedGroup.severity]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
							className: "statusBadge",
							children: [selectedGroup.resources, " resources"]
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: selectedGroup.title }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", { children: selectedGroup.id }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "groupStats",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: selectedGroup.fail }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Failed" })] }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: selectedGroup.pass }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Passed" })] }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: selectedGroup.findings.length }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("small", { children: "Rows" })] })
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", { children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "Affected resource findings" }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Open a resource to review evidence, remediation, and every other check affecting it." }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "resourceList",
							children: selectedGroup.findings.slice(0, 100).map((finding, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								onClick: () => {
									setSelectedGroup(null);
									setSelected(finding);
								},
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: `resourceStatus ${finding.status.toLowerCase()}`,
										children: finding.status
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: finding.asset }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("small", { children: [
										finding.location,
										" · ",
										finding.category
									] })] }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppIcon, { name: "chevron" })
								]
							}, `${finding.asset}-${index}`))
						}),
						selectedGroup.findings.length > 100 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "listLimit",
							children: [
								"Showing the first 100 of ",
								selectedGroup.findings.length.toLocaleString(),
								" rows. Use filters to narrow the group."
							]
						})
					] })
				]
			})
		}),
		selected && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "drawerBackdrop",
			onClick: () => setSelected(null),
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
				className: "drawer",
				onClick: (e) => e.stopPropagation(),
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						className: "close",
						onClick: () => setSelected(null),
						"aria-label": "Close details",
						children: "×"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "drawerTop",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: `severityBadge ${selected.severity}`,
							children: severityLabel[selected.severity]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "statusBadge",
							children: selected.status
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { children: selected.title }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", { children: selected.id }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", { children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", { children: "Asset / target" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", { children: selected.asset })] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", { children: "Location" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", { children: selected.location })] }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", { children: "Category" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", { children: selected.category })] })
					] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "What was found" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: selected.detail })] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
						className: "recommendation",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "Recommended action" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: selected.recommendation })]
					}),
					relatedFindings.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "Other findings on this resource" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "relatedList",
						children: relatedFindings.map((finding, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							onClick: () => setSelected(finding),
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: `severityDot ${finding.severity}` }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: finding.title }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("small", { children: [
								finding.status,
								" · ",
								finding.id
							] })] })]
						}, `${finding.id}-${index}`))
					})] }),
					selected.references.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", { children: "References" }), selected.references.slice(0, 5).map((reference) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
						href: reference,
						target: "_blank",
						rel: "noreferrer",
						children: reference
					}, reference))] })
				]
			})
		})
	] });
}
//#endregion
export { Home as default, parseProwler, parseProwlerCompliance, parseTrivy, parseZap };
