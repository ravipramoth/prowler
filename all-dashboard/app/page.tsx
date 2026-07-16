"use client";

import { ChangeEvent, DragEvent, useEffect, useMemo, useRef, useState } from "react";
import { Amplify, type ResourcesConfig } from "aws-amplify";
import { downloadData, uploadData } from "aws-amplify/storage";
import { Authenticator } from "@aws-amplify/ui-react";
import outputs from "../amplify_outputs.json";

type Scanner = "prowler" | "zap" | "trivy";
type Severity = "critical" | "high" | "medium" | "low" | "info";

type Finding = {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  asset: string;
  location: string;
  category: string;
  detail: string;
  recommendation: string;
  references: string[];
  raw: Record<string, unknown>;
};

type ComplianceSummary = {
  fileName: string;
  framework: string;
  total: number;
  pass: number;
  fail: number;
  manual: number;
  requirements: number;
  checks: number;
  passRate: number;
};

type ScanData = {
  fileName: string;
  importedAt: string;
  findings: Finding[];
  meta: Record<string, string | number>;
  compliance?: ComplianceSummary[];
};

type ChatMessage = { role: "user" | "assistant"; text: string };
type FindingGroup = { key: string; id: string; title: string; severity: Severity; category: string; findings: Finding[]; resources: number; fail: number; pass: number };
type CloudSnapshot = { version: 1; scanner: Scanner; savedAt: string; data: ScanData };

const cloudConfigured = Boolean((outputs as { auth?: unknown; storage?: unknown }).auth && (outputs as { storage?: unknown }).storage);
if (cloudConfigured) Amplify.configure(outputs as ResourcesConfig, { ssr: true });

const snapshotPath = (scanner: Scanner) => ({ identityId }: { identityId?: string }) => {
  if (!identityId) throw new Error("Your signed-in storage identity is unavailable.");
  return `scans/${identityId}/${scanner}/current.json`;
};

const scannerMeta: Record<Scanner, { name: string; short: string; accepts: string; accent: string; description: string }> = {
  prowler: { name: "Prowler", short: "PR", accepts: ".csv,text/csv", accent: "#ff8a3d", description: "Cloud posture & compliance" },
  zap: { name: "OWASP ZAP", short: "ZP", accepts: ".json,application/json", accent: "#7c6cff", description: "Web application security" },
  trivy: { name: "Trivy", short: "TV", accepts: ".json,application/json", accent: "#16b8a6", description: "Images, code & infrastructure" },
};

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const severityLabel: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function normalizeSeverity(value: unknown): Severity {
  const text = String(value ?? "").toLowerCase().trim();
  if (text.includes("critical") || text === "4") return "critical";
  if (text.includes("high") || text === "3") return "high";
  if (text.includes("medium") || text.includes("moderate") || text === "2") return "medium";
  if (text.includes("low") || text === "1") return "low";
  return "info";
}

function valueAt(record: Record<string, unknown>, aliases: string[]): unknown {
  const normalized = Object.fromEntries(Object.entries(record).map(([key, value]) => [key.toLowerCase().replace(/[ _-]/g, ""), value]));
  for (const alias of aliases) {
    const value = normalized[alias.toLowerCase().replace(/[ _-]/g, "")];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return "";
}

function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [], cell = "", quoted = false;
  const input = text.replace(/^\uFEFF/, "");
  const delimiterCounts = { ",": 0, ";": 0, "\t": 0 };
  let headerQuoted = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === '"' && input[i + 1] === '"' && headerQuoted) { i++; continue; }
    if (char === '"') { headerQuoted = !headerQuoted; continue; }
    if (!headerQuoted && char === "\n") break;
    if (!headerQuoted && char in delimiterCounts) delimiterCounts[char as keyof typeof delimiterCounts]++;
  }
  const knownHeaders = new Set([
    "checkid", "findinguid", "resourceuid", "status", "findingstatus", "severity",
    "requirementsid", "servicename", "checktitle", "resourcename", "region",
  ]);
  const firstLine = input.split(/\r?\n/, 1)[0] ?? "";
  const delimiter = Object.keys(delimiterCounts).sort((a, b) => {
    const score = (candidate: string) => firstLine.split(candidate)
      .map((header) => header.replace(/^\s*"|"\s*$/g, "").trim().toLowerCase().replace(/[ _-]/g, ""))
      .filter((header) => knownHeaders.has(header)).length * 1000 + delimiterCounts[candidate as keyof typeof delimiterCounts];
    return score(b) - score(a);
  })[0] || ",";
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') { cell += '"'; i++; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === delimiter) { row.push(cell); cell = ""; }
    else if (char === "\n") { row.push(cell.replace(/\r$/, "")); rows.push(row); row = []; cell = ""; }
    else cell += char;
  }
  if (cell.length || row.length) { row.push(cell.replace(/\r$/, "")); rows.push(row); }
  if (quoted) throw new Error("The CSV contains an unclosed quoted field.");
  const nonEmpty = rows.filter((r) => r.some((v) => v.trim()));
  if (nonEmpty.length < 2) throw new Error("The Prowler CSV has no finding rows.");
  const headers = nonEmpty[0].map((h) => h.trim());
  return nonEmpty.slice(1).map((values) => Object.fromEntries(headers.map((header, i) => [header, values[i] ?? ""])));
}

function parseDamagedProwlerCsv(text: string): Record<string, string>[] {
  const physicalLines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  const cleanLine = (line: string) => line.replace(/,{2,}\s*$/, "");
  const headerLine = cleanLine(physicalLines.shift() ?? "");
  const headers = headerLine.split(";").map((header) => header.trim().replace(/^"|"$/g, ""));
  const normalizedHeaders = headers.map((header) => header.toLowerCase().replace(/[ _-]/g, ""));
  if (!normalizedHeaders.includes("checkid") || !normalizedHeaders.includes("status") || !normalizedHeaders.includes("timestamp")) return [];

  // These exports contain malformed multiline quoted fields. A genuine Prowler
  // record still has a stable AUTH_METHOD;TIMESTAMP prefix, so use that boundary
  // and keep embedded newlines inside the current finding.
  const recordStart = /^[^;\r\n]+;\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?;/;
  const blocks: string[] = [];
  let current = "";
  for (const sourceLine of physicalLines) {
    const line = cleanLine(sourceLine);
    if (recordStart.test(line)) {
      if (current) blocks.push(current);
      current = line;
    } else if (current) {
      current += `\n${line}`;
    }
  }
  if (current) blocks.push(current);

  const cleanValue = (value: string) => value.trim().replace(/^"+|"+$/g, "").replace(/""/g, '"');
  return blocks.map((block) => {
    const values = block.split(";");
    const row: Record<string, string> = {};
    // Columns through the remediation URL precede the free-form IaC/code
    // columns where stray semicolons occur, and are therefore recoverable.
    const reliableColumns = Math.min(headers.length, 31);
    for (let index = 0; index < reliableColumns; index++) row[headers[index]] = cleanValue(values[index] ?? "");
    return row;
  }).filter((row) => valueAt(row, ["check_id", "finding_uid"]) && valueAt(row, ["status"]));
}

function normalizeProwlerRows(rows: Record<string, string>[]): Finding[] {
  return rows.map((raw, index): Finding => {
    const checkId = String(valueAt(raw, ["check_id", "checkid", "finding_uid", "findinguid"]) || `row-${index + 1}`);
    const status = String(valueAt(raw, ["status", "finding_status", "findingstatus"]) || "UNKNOWN").toUpperCase();
    const service = String(valueAt(raw, ["service_name", "servicename", "service"]) || "Unspecified service");
    const resource = String(valueAt(raw, ["resource_name", "resourcename", "resource_uid", "resourceuid", "resource_arn", "resourcearn"]) || "No resource supplied");
    return {
      id: checkId,
      title: String(valueAt(raw, ["check_title", "checktitle", "finding_title", "findingtitle", "title"]) || checkId),
      severity: normalizeSeverity(valueAt(raw, ["severity", "risk"])),
      status,
      asset: resource,
      location: String(valueAt(raw, ["region", "location", "account_name", "accountname"]) || "Global"),
      category: service,
      detail: String(valueAt(raw, ["status_extended", "statusextended", "description"]) || "No detail supplied"),
      recommendation: String(valueAt(raw, ["remediation_recommendation_text", "remediationrecommendationtext", "remediation", "recommendation"]) || "Review the Prowler remediation guidance."),
      references: String(valueAt(raw, ["remediation_recommendation_url", "remediationrecommendationurl", "references"]) || "").split(/[|,]/).filter(Boolean),
      raw,
    };
  });
}

function deduplicateProwlerFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, { finding: Finding; timestamp: string; timestamps: Set<string>; occurrences: number }>();
  findings.forEach((finding) => {
    const account = String(valueAt(finding.raw, ["account_uid", "accountuid", "account_name", "accountname"]));
    const resource = String(valueAt(finding.raw, ["resource_uid", "resourceuid", "resource_arn", "resourcearn"]) || valueAt(finding.raw, ["finding_uid", "findinguid"]) || finding.asset);
    const timestamp = String(valueAt(finding.raw, ["timestamp"]));
    const key = `${account}\u0000${finding.id}\u0000${resource}`;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, { finding, timestamp, timestamps: new Set(timestamp ? [timestamp] : []), occurrences: 1 });
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
      scan_timestamps: Array.from(timestamps).sort().join(" | "),
    },
  }));
}

function parseProwler(text: string): ScanData {
  let rows: Record<string, string>[];
  let recovered = false;
  try {
    rows = parseCsv(text);
  } catch {
    rows = parseDamagedProwlerCsv(text);
    recovered = rows.length > 0;
  }
  const columns = Object.keys(rows[0] ?? {}).map((key) => key.toLowerCase().replace(/[ _-]/g, ""));
  const hasIdentity = columns.some((key) => ["checkid", "findinguid", "resourceuid"].includes(key));
  const hasStatus = columns.some((key) => ["status", "findingstatus"].includes(key));
  const recognizedStatuses = rows.filter((row) => ["PASS", "FAIL", "MANUAL", "MUTED"].includes(String(valueAt(row, ["status", "finding_status", "findingstatus"])).toUpperCase())).length;
  const implausibleRows = rows.length > 0 && recognizedStatuses / rows.length < 0.5;
  if (!hasIdentity || !hasStatus || implausibleRows) {
    const recoveredRows = parseDamagedProwlerCsv(text);
    if (recoveredRows.length) { rows = recoveredRows; recovered = true; }
    else throw new Error("This CSV does not match a Prowler export. A check/finding ID and status column are required.");
  }
  const normalized = normalizeProwlerRows(rows);
  const findings = deduplicateProwlerFindings(normalized);
  const scanRuns = new Set(rows.map((row) => String(valueAt(row, ["timestamp"]))).filter(Boolean)).size;
  return {
    fileName: "",
    importedAt: new Date().toISOString(),
    findings,
    meta: {
      "scan rows": rows.length,
      "scan runs": scanRuns || 1,
      "unique findings": findings.length,
      failed: findings.filter((finding) => finding.status === "FAIL").length,
      passed: findings.filter((finding) => finding.status === "PASS").length,
      ...(recovered ? { format: "Recovered Prowler CSV" } : {}),
    },
  };
}

function frameworkNameFromFile(fileName: string, row: Record<string, string>): string {
  const cisVersion = fileName.match(/_cis_([\d.]+)_azure/i)?.[1];
  if (cisVersion) return `CIS Azure ${cisVersion}`;
  const base = fileName.replace(/\.csv$/i, "").replace(/^nava-scan-full-jul\d+_/i, "").replace(/_azure$/i, "");
  const labels: Record<string, string> = {
    "c5": "C5", "ccc": "CCC", "cis_controls_8.1": "CIS Controls 8.1", "csa_ccm_4.0": "CSA CCM 4.0",
    "dora_2022_2554": "DORA 2022/2554", "ens_rd2022": "ENS RD2022", "fedramp_20x_ksi_low": "FedRAMP 20x KSI Low",
    "hipaa": "HIPAA", "iso27001_2022": "ISO 27001:2022", "mitre_attack": "MITRE ATT&CK", "nis2": "NIS2", "pci_4.0": "PCI DSS 4.0",
    "prowler_threatscore": "Prowler ThreatScore", "rbi_cyber_security_framework": "RBI Cyber Security Framework",
    "secnumcloud_3.2": "SecNumCloud 3.2", "soc2": "SOC 2",
  };
  return labels[base.toLowerCase()] ?? String(valueAt(row, ["framework"]) || base.replace(/_/g, " ").toUpperCase());
}

function parseProwlerCompliance(text: string, fileName: string): ComplianceSummary {
  const rows = parseCsv(text);
  const columns = Object.keys(rows[0] ?? {}).map((key) => key.toLowerCase().replace(/[ _-]/g, ""));
  if (!columns.includes("requirementsid") || !columns.includes("status")) throw new Error("This is not a Prowler compliance CSV.");
  const statuses = { pass: 0, fail: 0, manual: 0 };
  const requirements = new Set<string>();
  const checks = new Set<string>();
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
    fileName, framework: frameworkNameFromFile(fileName, rows[0]), total: rows.length,
    pass: statuses.pass, fail: statuses.fail, manual: statuses.manual,
    requirements: requirements.size, checks: checks.size,
    passRate: automated ? Math.round((statuses.pass / automated) * 1000) / 10 : 0,
  };
}

function parseZap(payload: unknown): ScanData {
  if (!payload || typeof payload !== "object") throw new Error("The ZAP JSON root must be an object.");
  const root = payload as Record<string, unknown>;
  const sites = Array.isArray(root.site) ? root.site : Array.isArray(root.sites) ? root.sites : [];
  if (!sites.length) throw new Error("No ZAP sites were found. Expected a JSON report with a site array.");
  const findings: Finding[] = [];
  let instanceCount = 0;
  let alertCount = 0;
  sites.forEach((siteValue, siteIndex) => {
    const site = (siteValue ?? {}) as Record<string, unknown>;
    const alerts = Array.isArray(site.alerts) ? site.alerts : [];
    alerts.forEach((alertValue, alertIndex) => {
      alertCount++;
      const alert = (alertValue ?? {}) as Record<string, unknown>;
      const instances = Array.isArray(alert.instances) ? alert.instances : [];
      instanceCount += instances.length;
      const endpointRows = instances.length ? instances : [{}];
      endpointRows.forEach((instanceValue, instanceIndex) => {
        const instance = (instanceValue ?? {}) as Record<string, unknown>;
        const evidence = [instance.method, instance.param && `parameter: ${instance.param}`, instance.evidence && `evidence: ${instance.evidence}`].filter(Boolean).join(" · ");
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
          raw: { ...alert, _instance: instance, _instanceIndex: instanceIndex },
        });
      });
    });
  });
  return { fileName: "", importedAt: new Date().toISOString(), findings, meta: { sites: sites.length, alerts: alertCount, instances: instanceCount } };
}

function parseTrivy(payload: unknown): ScanData {
  if (!payload || typeof payload !== "object") throw new Error("The Trivy JSON root must be an object.");
  const root = payload as Record<string, unknown>;
  const hasResults = Array.isArray(root.Results) || Array.isArray(root.results);
  const results = Array.isArray(root.Results) ? root.Results : Array.isArray(root.results) ? root.results : [];
  if (!hasResults) throw new Error("No Trivy Results array was found in this report.");
  const findings: Finding[] = [];
  results.forEach((resultValue, resultIndex) => {
    const result = (resultValue ?? {}) as Record<string, unknown>;
    const target = String(result.Target ?? result.target ?? "Unknown target");
    const source = String(result.Class ?? result.Type ?? "Trivy");
    const groups: [string, unknown[]][] = [
      ["Vulnerability", Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : []],
      ["Misconfiguration", Array.isArray(result.Misconfigurations) ? result.Misconfigurations : []],
      ["Secret", Array.isArray(result.Secrets) ? result.Secrets : []],
      ["License", Array.isArray(result.Licenses) ? result.Licenses : []],
    ];
    groups.forEach(([kind, entries]) => entries.forEach((entryValue, entryIndex) => {
      const entry = (entryValue ?? {}) as Record<string, unknown>;
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
        references: [entry.PrimaryURL, ...(Array.isArray(entry.References) ? entry.References : [])].filter(Boolean).map(String),
        raw: entry,
      });
    }));
  });
  return { fileName: "", importedAt: new Date().toISOString(), findings, meta: { targets: results.length, findings: findings.length, artifact: String(root.ArtifactName ?? root.ArtifactType ?? "Trivy report") } };
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function AppIcon({ name }: { name: "grid" | "upload" | "search" | "shield" | "file" | "chevron" | "check" }) {
  const glyph = { grid: "▦", upload: "↥", search: "⌕", shield: "◇", file: "▤", chevron: "›", check: "✓" }[name];
  return <span className="glyph" aria-hidden="true">{glyph}</span>;
}

function Dashboard({ cloudEnabled, userEmail, onSignOut }: { cloudEnabled: boolean; userEmail?: string; onSignOut?: () => void }) {
  const [active, setActive] = useState<Scanner>("prowler");
  const [data, setData] = useState<Partial<Record<Scanner, ScanData>>>({});
  const [cloudBusy, setCloudBusy] = useState(cloudEnabled);
  const [cloudStatus, setCloudStatus] = useState(cloudEnabled ? "Restoring saved reports…" : "Local processing only");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [resultStatus, setResultStatus] = useState<"all" | "FAIL" | "PASS">("all");
  const [prowlerView, setProwlerView] = useState<"findings" | "compliance">("findings");
  const [inventoryMode, setInventoryMode] = useState<"issues" | "resources">("issues");
  const [serviceFilter, setServiceFilter] = useState("all");
  const [regionFilter, setRegionFilter] = useState("all");
  const [selectedGroup, setSelectedGroup] = useState<FindingGroup | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [dragging, setDragging] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [copilotConfigured, setCopilotConfigured] = useState<boolean | null>(null);
  const [copilotModel, setCopilotModel] = useState("gpt-5.4-mini");
  const [copilotInput, setCopilotInput] = useState("");
  const [copilotBusy, setCopilotBusy] = useState(false);
  const [copilotMessages, setCopilotMessages] = useState<ChatMessage[]>([{ role: "assistant", text: "Import a scan, then ask me to prioritize risks, explain a finding, or create a remediation plan." }]);
  const inputRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const current = data[active];

  useEffect(() => {
    if (!cloudEnabled) return;
    let cancelled = false;
    async function restoreSnapshots() {
      setCloudBusy(true);
      try {
        const restored = await Promise.all((["prowler", "zap", "trivy"] as Scanner[]).map(async (scanner) => {
          try {
            const result = await downloadData({ path: snapshotPath(scanner) }).result;
            const snapshot = JSON.parse(await result.body.text()) as CloudSnapshot;
            if (snapshot.version !== 1 || snapshot.scanner !== scanner || !Array.isArray(snapshot.data?.findings)) throw new Error(`The saved ${scanner} report is invalid.`);
            return [scanner, snapshot.data] as const;
          } catch (reason) {
            const message = reason instanceof Error ? `${reason.name} ${reason.message}` : String(reason);
            if (/NoSuchKey|NotFound|404|does not exist/i.test(message)) return null;
            throw reason;
          }
        }));
        if (cancelled) return;
        const available = restored.filter((entry): entry is readonly [Scanner, ScanData] => entry !== null);
        if (available.length) setData(Object.fromEntries(available) as Partial<Record<Scanner, ScanData>>);
        setCloudStatus(available.length ? `${available.length} saved report${available.length === 1 ? "" : "s"} restored` : "Private cloud storage ready");
      } catch (reason) {
        if (!cancelled) {
          setError(reason instanceof Error ? `Could not restore saved reports: ${reason.message}` : "Could not restore saved reports.");
          setCloudStatus("Cloud restore needs attention");
        }
      } finally {
        if (!cancelled) setCloudBusy(false);
      }
    }
    void restoreSnapshots();
    return () => { cancelled = true; };
  }, [cloudEnabled]);

  const statusFindings = useMemo(() => {
    if (!current) return [];
    if (active !== "prowler" || resultStatus === "all") return current.findings;
    return current.findings.filter((finding) => finding.status === resultStatus);
  }, [active, current, resultStatus]);

  const visible = useMemo(() => {
    if (!current) return [];
    const term = query.toLowerCase().trim();
    return statusFindings.filter((finding) => (severity === "all" || finding.severity === severity) && (serviceFilter === "all" || finding.category === serviceFilter) && (regionFilter === "all" || finding.location === regionFilter) && (!term || [finding.id, finding.title, finding.asset, finding.location, finding.category, finding.status].join(" ").toLowerCase().includes(term)));
  }, [current, query, severity, serviceFilter, regionFilter, statusFindings]);

  const findingGroups = useMemo(() => {
    const groups = new Map<string, Finding[]>();
    visible.forEach((finding) => { const key = `${finding.id}|${finding.title}`; groups.set(key, [...(groups.get(key) ?? []), finding]); });
    return Array.from(groups, ([key, findings]): FindingGroup => {
      const first = findings[0];
      return { key, id: first.id, title: first.title, severity: findings.reduce((highest, finding) => severityRank[finding.severity] < severityRank[highest] ? finding.severity : highest, first.severity), category: first.category, findings, resources: new Set(findings.map((finding) => finding.asset)).size, fail: findings.filter((finding) => finding.status === "FAIL").length, pass: findings.filter((finding) => finding.status === "PASS").length };
    }).sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || b.fail - a.fail || b.resources - a.resources);
  }, [visible]);

  const serviceOptions = useMemo(() => Array.from(new Set(statusFindings.map((finding) => finding.category).filter(Boolean))).sort(), [statusFindings]);
  const regionOptions = useMemo(() => Array.from(new Set(statusFindings.map((finding) => finding.location).filter(Boolean))).sort(), [statusFindings]);
  const relatedFindings = useMemo(() => selected && current ? current.findings.filter((finding) => finding.asset === selected.asset && !(finding.id === selected.id && finding.title === selected.title)).slice(0, 12) : [], [current, selected]);

  const counts = useMemo(() => Object.fromEntries(severityOrder.map((level) => [level, statusFindings.filter((f) => f.severity === level).length])) as Record<Severity, number>, [statusFindings]);
  const prowlerStatusCounts = useMemo(() => ({
    fail: current?.findings.filter((finding) => finding.status === "FAIL").length ?? 0,
    pass: current?.findings.filter((finding) => finding.status === "PASS").length ?? 0,
  }), [current]);
  const complianceTotals = useMemo(() => {
    const items = current?.compliance ?? [];
    const totals = items.reduce((sum, item) => ({ total: sum.total + item.total, pass: sum.pass + item.pass, fail: sum.fail + item.fail, manual: sum.manual + item.manual }), { total: 0, pass: 0, fail: 0, manual: 0 });
    const automated = totals.pass + totals.fail;
    return { ...totals, frameworks: items.length, passRate: automated ? Math.round((totals.pass / automated) * 1000) / 10 : 0 };
  }, [current]);

  async function importFiles(selectedFiles: File[]) {
    setError(""); setSelected(null); setSelectedGroup(null); setQuery(""); setSeverity("all"); setResultStatus("all"); setServiceFilter("all"); setRegionFilter("all");
    try {
      const files = active === "zap" ? selectedFiles.filter((file) => file.name.toLowerCase().endsWith(".json")) : active === "prowler" ? selectedFiles.filter((file) => file.name.toLowerCase().endsWith(".csv")) : selectedFiles.slice(0, 1);
      if (!files.length) throw new Error(active === "zap" ? "No JSON reports were found in this selection." : "No report was selected.");
      const reports: ScanData[] = [];
      const compliance: ComplianceSummary[] = [];
      for (const file of files) {
        const text = await file.text();
        let parsed: ScanData;
        if (active === "prowler") {
          const header = text.slice(0, text.indexOf("\n") === -1 ? 4000 : text.indexOf("\n")).toLowerCase().replace(/[ _-]/g, "");
          if (header.includes("requirementsid")) { compliance.push(parseProwlerCompliance(text, file.name)); continue; }
          parsed = parseProwler(text);
        }
        else {
          let json: unknown;
          try { json = JSON.parse(text.replace(/^\uFEFF/, "")); } catch { throw new Error(`${file.name} is not valid JSON.`); }
          try { parsed = active === "zap" ? parseZap(json) : parseTrivy(json); }
          catch (reason) { throw new Error(`${file.name}: ${reason instanceof Error ? reason.message : "The report could not be read."}`); }
        }
        parsed.fileName = file.name;
        reports.push(parsed);
      }
      let parsed: ScanData;
      if (active === "prowler") {
        const core = reports.flatMap((report) => report.findings);
        const selectedCount = selectedFiles.length;
        parsed = {
          fileName: selectedCount > 1 ? `${selectedCount} Prowler export files` : reports[0]?.fileName ?? `${compliance.length} compliance reports`,
          importedAt: new Date().toISOString(), findings: core, compliance: compliance.sort((a, b) => a.framework.localeCompare(b.framework)),
          meta: { files: selectedCount, findings: core.length, frameworks: compliance.length, "compliance rows": compliance.reduce((sum, item) => sum + item.total, 0) },
        };
      } else if (active === "zap" && reports.length > 1) parsed = {
        fileName: `${reports.length} ZAP endpoint reports`,
        importedAt: new Date().toISOString(),
        findings: reports.flatMap((report) => report.findings),
        meta: {
          files: reports.length,
          sites: reports.reduce((sum, report) => sum + Number(report.meta.sites ?? 0), 0),
          alerts: reports.reduce((sum, report) => sum + Number(report.meta.alerts ?? 0), 0),
          instances: reports.reduce((sum, report) => sum + Number(report.meta.instances ?? 0), 0),
        },
      } satisfies ScanData;
      else parsed = reports[0];
      setData((previous) => ({ ...previous, [active]: parsed }));
      if (cloudEnabled) {
        setCloudBusy(true);
        setCloudStatus(`Saving ${scannerMeta[active].name}…`);
        try {
          const snapshot: CloudSnapshot = { version: 1, scanner: active, savedAt: new Date().toISOString(), data: parsed };
          await uploadData({
            path: snapshotPath(active),
            data: JSON.stringify(snapshot),
            options: { contentType: "application/json" },
          }).result;
          setCloudStatus(`${scannerMeta[active].name} saved privately`);
        } catch (reason) {
          setCloudStatus("Cloud save needs attention");
          setError(reason instanceof Error ? `The report loaded, but cloud storage could not save it: ${reason.message}` : "The report loaded, but cloud storage could not save it.");
        } finally {
          setCloudBusy(false);
        }
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The file could not be read.");
    }
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? []); if (files.length) void importFiles(files); event.target.value = "";
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault(); setDragging(false); const files = Array.from(event.dataTransfer.files ?? []); if (files.length) void importFiles(files);
  }

  function exportVisible() {
    const headers = ["id", "title", "severity", "status", "asset", "location", "category", "detail", "recommendation"];
    const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;
    const csv = [headers.join(","), ...visible.map((f) => headers.map((key) => escape(String(f[key as keyof Finding] ?? ""))).join(","))].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `${active}-filtered-findings.csv`; anchor.click(); URL.revokeObjectURL(url);
  }

  async function openCopilot() {
    setCopilotOpen(true);
    if (copilotConfigured !== null) return;
    try {
      const response = await fetch("/api/security-chat");
      const config = await response.json() as { configured?: boolean; model?: string };
      setCopilotConfigured(Boolean(config.configured));
      if (config.model) setCopilotModel(config.model);
    } catch { setCopilotConfigured(false); }
  }

  async function sendCopilot(question: string) {
    const trimmed = question.trim();
    if (!trimmed || copilotBusy) return;
    if (!current) {
      setCopilotMessages((messages) => [...messages, { role: "assistant", text: "Import a Prowler, ZAP, or Trivy report first so I have evidence to analyze." }]);
      return;
    }
    if (!copilotConfigured) return;
    const priority = Object.fromEntries(severityOrder.map((level, index) => [level, index])) as Record<Severity, number>;
    const candidates = current.findings
      .filter((finding) => active !== "prowler" || finding.status === "FAIL")
      .sort((a, b) => priority[a.severity] - priority[b.severity])
      .slice(0, 50)
      .map(({ id, title, severity: findingSeverity, status, asset, location, category, detail, recommendation }) => ({ id, title, severity: findingSeverity, status, asset, location, category, detail, recommendation }));
    if (!candidates.length) {
      setCopilotMessages((messages) => [...messages, { role: "assistant", text: "This report has no actionable failed or detected findings to analyze." }]);
      return;
    }
    setCopilotMessages((messages) => [...messages, { role: "user", text: trimmed }]);
    setCopilotInput(""); setCopilotBusy(true);
    try {
      const response = await fetch("/api/security-chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: trimmed, scanner: scannerMeta[active].name, findings: candidates }) });
      const result = await response.json() as { answer?: string; error?: string; model?: string };
      if (!response.ok || !result.answer) throw new Error(result.error || "Security Copilot could not complete the analysis.");
      if (result.model) setCopilotModel(result.model);
      setCopilotMessages((messages) => [...messages, { role: "assistant", text: result.answer! }]);
    } catch (reason) {
      setCopilotMessages((messages) => [...messages, { role: "assistant", text: reason instanceof Error ? reason.message : "Security Copilot could not complete the analysis." }]);
    } finally { setCopilotBusy(false); }
  }

  return (
    <main>
      <header className="topbar">
        <div className="brand"><span className="brandMark"><AppIcon name="shield" /></span><span>Sentinel<span className="brandAccent">Scope</span></span></div>
        <div className="workspace"><span className="workspaceDot" /> Security workspace <span className="workspaceArrow">⌄</span></div>
        <div className="topActions"><div className="privacy"><span className={`privacyDot ${cloudBusy ? "syncing" : ""}`} /> {cloudStatus}</div>{userEmail && <span className="userEmail">{userEmail}</span>}<button className="copilotButton" onClick={() => void openCopilot()}><span>✦</span> Security Copilot</button>{onSignOut && <button className="signOutButton" onClick={onSignOut}>Sign out</button>}</div>
      </header>

      <section className="shell">
        <aside className="sidebar">
          <div className="sideLabel">SCANNERS</div>
          {(["prowler", "zap", "trivy"] as Scanner[]).map((scanner) => {
            const meta = scannerMeta[scanner];
            return <button key={scanner} className={`sideItem ${active === scanner ? "active" : ""}`} onClick={() => { setActive(scanner); setError(""); setQuery(""); setSeverity("all"); setResultStatus("all"); setServiceFilter("all"); setRegionFilter("all"); setProwlerView("findings"); setSelected(null); setSelectedGroup(null); }}>
              <span className="scannerIcon" style={{ "--accent": meta.accent } as React.CSSProperties}>{meta.short}</span>
              <span><strong>{meta.name}</strong><small>{meta.description}</small></span>
              {data[scanner] && <span className="loaded"><AppIcon name="check" /></span>}
            </button>;
          })}
          <div className="sideFoot"><AppIcon name="shield" /><div><strong>Your data stays here</strong><p>Files are parsed in your browser and are never uploaded.</p></div></div>
        </aside>

        <div className="content">
          <div className="pageHead">
            <div><div className="eyebrow"><span style={{ background: scannerMeta[active].accent }} /> {active === "prowler" && prowlerView === "compliance" ? "Cloud compliance & control mappings" : scannerMeta[active].description}</div><h1>{active === "prowler" && prowlerView === "compliance" ? "Prowler compliance" : `${scannerMeta[active].name} findings`}</h1><p>{active === "prowler" && prowlerView === "compliance" ? "Compare framework pass rates, failures, manual reviews, requirements, and mapped checks." : "Import, inspect, filter, and export every finding from your scan report."}</p></div>
            {current && <button className="secondaryButton" onClick={() => inputRef.current?.click()}><AppIcon name="upload" /> Replace report</button>}
          </div>

          <nav className="tabs" aria-label="Scanner report tabs">
            <button className={active === "prowler" && prowlerView === "findings" ? "active" : ""} onClick={() => { setActive("prowler"); setProwlerView("findings"); setError(""); setSeverity("all"); setResultStatus("all"); setServiceFilter("all"); setRegionFilter("all"); setSelected(null); setSelectedGroup(null); }}>Prowler{data.prowler && <span>{data.prowler.findings.length}</span>}</button>
            <button className={active === "prowler" && prowlerView === "compliance" ? "active" : ""} onClick={() => { setActive("prowler"); setProwlerView("compliance"); setError(""); setSeverity("all"); setResultStatus("all"); setServiceFilter("all"); setRegionFilter("all"); setSelected(null); setSelectedGroup(null); }}>Compliance{data.prowler?.compliance?.length ? <span>{data.prowler.compliance.length}</span> : null}</button>
            {(["zap", "trivy"] as Scanner[]).map((scanner) => <button key={scanner} className={active === scanner ? "active" : ""} onClick={() => { setActive(scanner); setError(""); setSeverity("all"); setResultStatus("all"); setServiceFilter("all"); setRegionFilter("all"); setProwlerView("findings"); setSelected(null); setSelectedGroup(null); }}>{scannerMeta[scanner].name}{data[scanner] && <span>{data[scanner]!.findings.length}</span>}</button>)}
          </nav>

          <input ref={inputRef} className="hiddenInput" type="file" accept={scannerMeta[active].accepts} multiple={active === "zap" || active === "prowler"} onChange={onFileChange} />
          {(active === "zap" || active === "prowler") && <input ref={folderRef} className="hiddenInput" type="file" accept={active === "zap" ? ".json,application/json" : ".csv,text/csv"} multiple onChange={onFileChange} {...({ webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement>)} />}
          {!current ? (
            <section className={`uploadCard ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}>
              <div className="uploadVisual"><span className="fileSheet"><AppIcon name="file" /></span><span className="uploadArrow"><AppIcon name="upload" /></span></div>
              <h2>{active === "zap" ? "Import all ZAP endpoint reports" : active === "prowler" ? "Import the complete Prowler export" : `Drop your ${scannerMeta[active].name} report here`}</h2>
              <p>{active === "prowler" ? "Select the core CSV and compliance CSVs together, or choose the entire export folder." : active === "zap" ? "Select every JSON report at once, choose the whole folder, or drop the files here." : `Choose a JSON report exported by ${scannerMeta[active].name}.`}</p>
              <div className="uploadActions"><button className="primaryButton" style={{ "--accent": scannerMeta[active].accent } as React.CSSProperties} onClick={() => inputRef.current?.click()}>{active === "zap" ? "Choose JSON reports" : active === "prowler" ? "Choose CSV reports" : "Choose report"}</button>{(active === "zap" || active === "prowler") && <button className="secondaryButton" onClick={() => folderRef.current?.click()}>Choose folder</button>}</div>
              <div className="supported"><span>SUPPORTED</span>{active === "prowler" ? "CSV · Comma or semicolon · Multiline quoted fields" : "JSON · Standard report schema"}</div>
              {error && <div className="errorBox" role="alert">{error}</div>}
            </section>
          ) : (
            <>
              {error && <div className="errorBox topError" role="alert">{error}</div>}
              <section className="reportMeta">
                <div><span className="fileBadge"><AppIcon name="file" /></span><div><strong>{current.fileName}</strong><small>Imported {formatDate(current.importedAt)} · {current.findings.length.toLocaleString()} unique findings{active === "prowler" ? " (latest result per check and full resource ID)" : ""}</small></div></div>
                <div className="metaStats">{Object.entries(current.meta).slice(0, 4).map(([key, value]) => <span key={key}><small>{key}</small><strong>{String(value)}</strong></span>)}</div>
              </section>

              {active === "prowler" && prowlerView === "compliance" ? <>
                <section className="complianceHero">
                  <div><small>FRAMEWORKS</small><strong>{complianceTotals.frameworks}</strong><p>Imported compliance standards</p></div>
                  <div><small>AUTOMATED PASS RATE</small><strong>{complianceTotals.passRate}%</strong><div className="complianceMeter"><i style={{ width: `${complianceTotals.passRate}%` }} /></div></div>
                  <div className="complianceStatus pass"><small>PASS ROWS</small><strong>{complianceTotals.pass.toLocaleString()}</strong></div>
                  <div className="complianceStatus fail"><small>FAIL ROWS</small><strong>{complianceTotals.fail.toLocaleString()}</strong></div>
                  <div className="complianceStatus manual"><small>MANUAL ROWS</small><strong>{complianceTotals.manual.toLocaleString()}</strong></div>
                </section>
                <section className="findingsPanel compliancePanel">
                  <div className="panelHead"><div><h2>Compliance framework inventory</h2><p>{complianceTotals.total.toLocaleString()} mapped control results across {complianceTotals.frameworks} frameworks; repeated mappings are intentionally kept within each framework.</p></div></div>
                  <div className="tableWrap"><table className="complianceTable"><thead><tr><th>Framework</th><th>Automated pass rate</th><th>Pass</th><th>Fail</th><th>Manual</th><th>Requirements</th><th>Checks</th></tr></thead><tbody>{current.compliance!.map((item) => <tr key={item.fileName}><td><strong>{item.framework}</strong><small>{item.fileName}</small></td><td><div className="rateCell"><span>{item.passRate}%</span><i><b style={{ width: `${item.passRate}%` }} /></i></div></td><td><span className="countPass">{item.pass.toLocaleString()}</span></td><td><span className="countFail">{item.fail.toLocaleString()}</span></td><td>{item.manual.toLocaleString()}</td><td>{item.requirements.toLocaleString()}</td><td>{item.checks.toLocaleString()}</td></tr>)}</tbody></table></div>
                </section>
              </> : <>

              {active === "prowler" && <section className="resultSwitch" aria-label="Prowler result category">
                <div><strong>Result category</strong><small>Review failed and passed checks separately</small></div>
                <div className="resultOptions">
                  <button className={resultStatus === "all" ? "active all" : "all"} onClick={() => { setResultStatus("all"); setSeverity("all"); }}>All checks <span>{current.findings.length}</span></button>
                  <button className={resultStatus === "FAIL" ? "active fail" : "fail"} onClick={() => { setResultStatus("FAIL"); setSeverity("all"); }}>Failed <span>{prowlerStatusCounts.fail}</span></button>
                  <button className={resultStatus === "PASS" ? "active pass" : "pass"} onClick={() => { setResultStatus("PASS"); setSeverity("all"); }}>Passed <span>{prowlerStatusCounts.pass}</span></button>
                </div>
              </section>}

              <section className="summaryGrid">
                <article className="totalCard"><div><small>{active === "prowler" && resultStatus !== "all" ? `${resultStatus} CHECKS` : "TOTAL FINDINGS"}</small><strong>{statusFindings.length.toLocaleString()}</strong><p>{visible.length === statusFindings.length ? (resultStatus === "all" ? "Across the complete report" : `of ${current.findings.length.toLocaleString()} total checks`) : `${visible.length.toLocaleString()} match current filters`}</p></div><div className="donut" style={{ background: `conic-gradient(#ef4b5f 0 ${statusFindings.length ? (counts.critical / statusFindings.length) * 100 : 0}%, #ff8a3d 0 ${statusFindings.length ? ((counts.critical + counts.high) / statusFindings.length) * 100 : 0}%, #f5be3d 0 ${statusFindings.length ? ((counts.critical + counts.high + counts.medium) / statusFindings.length) * 100 : 0}%, #67b7a8 0 100%)` }}><span>{statusFindings.length ? Math.round(((counts.critical + counts.high) / statusFindings.length) * 100) : 0}%<small>urgent</small></span></div></article>
                {severityOrder.map((level) => <button key={level} className={`severityCard ${level} ${severity === level ? "selected" : ""}`} onClick={() => setSeverity(severity === level ? "all" : level)}><span className="severityLine" /><small>{severityLabel[level].toUpperCase()}</small><strong>{counts[level].toLocaleString()}</strong><div className="miniBar"><i style={{ width: `${statusFindings.length ? Math.max(3, (counts[level] / statusFindings.length) * 100) : 0}%` }} /></div></button>)}
              </section>

              <section className="findingsPanel">
                <div className="panelHead"><div><h2>{active === "prowler" && inventoryMode === "issues" ? "Issues grouped by check" : active === "prowler" && resultStatus !== "all" ? `${resultStatus === "FAIL" ? "Failed" : "Passed"} check inventory` : "Finding inventory"}</h2><p>{active === "prowler" && inventoryMode === "issues" ? `${findingGroups.length.toLocaleString()} issue types across ${visible.length.toLocaleString()} unique resource findings` : `Showing ${visible.length.toLocaleString()} of ${statusFindings.length.toLocaleString()} ${active === "prowler" ? "unique resource findings" : "findings"}`}</p></div><div className="panelActions">{active === "prowler" && <div className="viewToggle"><button className={inventoryMode === "issues" ? "active" : ""} onClick={() => setInventoryMode("issues")}>Issues</button><button className={inventoryMode === "resources" ? "active" : ""} onClick={() => setInventoryMode("resources")}>All resources</button></div>}<button className="textButton" onClick={exportVisible} disabled={!visible.length}>Export filtered CSV <AppIcon name="chevron" /></button></div></div>
                <div className="toolbar">
                  <label className="search"><AppIcon name="search" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search ID, asset, finding or location…" /><kbd>⌘ K</kbd></label>
                  {active === "prowler" && <div className="facetFilters"><select value={serviceFilter} onChange={(event) => setServiceFilter(event.target.value)} aria-label="Filter by service"><option value="all">All services</option>{serviceOptions.map((service) => <option key={service} value={service}>{service}</option>)}</select><select value={regionFilter} onChange={(event) => setRegionFilter(event.target.value)} aria-label="Filter by region"><option value="all">All regions</option>{regionOptions.map((region) => <option key={region} value={region}>{region}</option>)}</select></div>}
                  <div className="filterPills"><button className={severity === "all" ? "active" : ""} onClick={() => setSeverity("all")}>All</button>{severityOrder.map((level) => <button key={level} className={severity === level ? "active" : ""} onClick={() => setSeverity(level)}>{severityLabel[level]} <span>{counts[level]}</span></button>)}</div>
                </div>
                <div className="tableWrap">
                  {active === "prowler" && inventoryMode === "issues" ? <table className="groupTable"><thead><tr><th>Severity</th><th>Issue / check</th><th>Affected resources</th><th>Service</th><th>Results</th><th aria-label="Open" /></tr></thead><tbody>{findingGroups.map((group) => <tr key={group.key} onClick={() => setSelectedGroup(group)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelectedGroup(group); }}><td><span className={`severityBadge ${group.severity}`}>{severityLabel[group.severity]}</span></td><td><strong>{group.title}</strong><small>{group.id}</small></td><td><strong>{group.resources.toLocaleString()} resources</strong><small>{group.findings.length.toLocaleString()} unique findings</small></td><td>{group.category}</td><td><span className="groupResult fail">{group.fail} fail</span><span className="groupResult pass">{group.pass} pass</span></td><td><AppIcon name="chevron" /></td></tr>)}</tbody></table> : <table><thead><tr><th>Severity</th><th>Finding</th><th>Asset / target</th><th>Category</th><th>Status</th><th aria-label="Open" /></tr></thead><tbody>{visible.map((finding, index) => <tr key={`${finding.id}-${index}`} onClick={() => setSelected(finding)} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter") setSelected(finding); }}><td><span className={`severityBadge ${finding.severity}`}>{severityLabel[finding.severity]}</span></td><td><strong>{finding.title}</strong><small>{finding.id}</small></td><td><strong>{finding.asset}</strong><small>{finding.location}</small></td><td>{finding.category}</td><td><span className="statusBadge">{finding.status}</span></td><td><AppIcon name="chevron" /></td></tr>)}</tbody></table>}
                  {!visible.length && <div className="emptyState"><AppIcon name="search" /><strong>No findings match</strong><p>Clear the search or select another severity.</p></div>}
                </div>
              </section>
              </>}
            </>
          )}
        </div>
      </section>

      {copilotOpen && <div className="copilotBackdrop" onClick={() => setCopilotOpen(false)}><aside className="copilotPanel" onClick={(e) => e.stopPropagation()}>
        <div className="copilotHead"><div className="copilotMark">✦</div><div><h2>Security Copilot</h2><p>{copilotModel} · analyzes only the context you send</p></div><button className="close" onClick={() => setCopilotOpen(false)} aria-label="Close Security Copilot">×</button></div>
        {copilotConfigured === false ? <div className="copilotSetup"><span className="setupIcon">⌁</span><h3>Connect the OpenAI API</h3><p>Keep your key on the local server. Create <code>.env.local</code>, add <code>OPENAI_API_KEY=your_key</code>, then restart SentinelScope.</p><a href="https://platform.openai.com/api-keys" target="_blank" rel="noreferrer">Open API key settings ↗</a><small>Do not paste your API key into this chat or the browser.</small></div> : <>
          <div className="contextBar"><span>{current ? scannerMeta[active].name : "No report"}</span><p>{current ? `Up to 50 highest-priority ${active === "prowler" ? "failed checks" : "findings"} will be sent with each question.` : "Import a report to provide analysis context."}</p></div>
          <div className="quickPrompts"><button disabled={!current || copilotBusy} onClick={() => void sendCopilot("Prioritize the most urgent issues and explain why they should be fixed first.")}>Prioritize risks</button><button disabled={!current || copilotBusy} onClick={() => void sendCopilot("Create a practical remediation plan grouped into quick wins, near-term work, and longer-term improvements.")}>Build fix plan</button><button disabled={!current || copilotBusy} onClick={() => void sendCopilot("Find the highest-impact quick wins and give exact validation steps after each fix.")}>Find quick wins</button></div>
          <div className="chatMessages">{copilotMessages.map((message, index) => <div key={index} className={`chatMessage ${message.role}`}><span>{message.role === "assistant" ? "✦" : "You"}</span><p>{message.text}</p></div>)}{copilotBusy && <div className="chatMessage assistant thinking"><span>✦</span><p>Reviewing scanner evidence…</p></div>}</div>
          <form className="chatComposer" onSubmit={(event) => { event.preventDefault(); void sendCopilot(copilotInput); }}><textarea value={copilotInput} onChange={(event) => setCopilotInput(event.target.value)} placeholder="Ask how to fix an issue…" rows={3} disabled={copilotBusy} /><div><small>Only summarized finding fields are sent.</small><button type="submit" disabled={!copilotInput.trim() || copilotBusy || !current}>Send ↗</button></div></form>
        </>}
      </aside></div>}

      {selectedGroup && <div className="drawerBackdrop" onClick={() => setSelectedGroup(null)}><aside className="drawer groupDrawer" onClick={(event) => event.stopPropagation()}><button className="close" onClick={() => setSelectedGroup(null)} aria-label="Close issue group">×</button><div className="drawerTop"><span className={`severityBadge ${selectedGroup.severity}`}>{severityLabel[selectedGroup.severity]}</span><span className="statusBadge">{selectedGroup.resources} resources</span></div><h2>{selectedGroup.title}</h2><code>{selectedGroup.id}</code><div className="groupStats"><span><strong>{selectedGroup.fail}</strong><small>Failed</small></span><span><strong>{selectedGroup.pass}</strong><small>Passed</small></span><span><strong>{selectedGroup.findings.length}</strong><small>Rows</small></span></div><section><h3>Affected resource findings</h3><p>Open a resource to review evidence, remediation, and every other check affecting it.</p><div className="resourceList">{selectedGroup.findings.slice(0, 100).map((finding, index) => <button key={`${finding.asset}-${index}`} onClick={() => { setSelectedGroup(null); setSelected(finding); }}><span className={`resourceStatus ${finding.status.toLowerCase()}`}>{finding.status}</span><div><strong>{finding.asset}</strong><small>{finding.location} · {finding.category}</small></div><AppIcon name="chevron" /></button>)}</div>{selectedGroup.findings.length > 100 && <p className="listLimit">Showing the first 100 of {selectedGroup.findings.length.toLocaleString()} rows. Use filters to narrow the group.</p>}</section></aside></div>}

      {selected && <div className="drawerBackdrop" onClick={() => setSelected(null)}><aside className="drawer" onClick={(e) => e.stopPropagation()}><button className="close" onClick={() => setSelected(null)} aria-label="Close details">×</button><div className="drawerTop"><span className={`severityBadge ${selected.severity}`}>{severityLabel[selected.severity]}</span><span className="statusBadge">{selected.status}</span></div><h2>{selected.title}</h2><code>{selected.id}</code><dl><div><dt>Asset / target</dt><dd>{selected.asset}</dd></div><div><dt>Location</dt><dd>{selected.location}</dd></div><div><dt>Category</dt><dd>{selected.category}</dd></div></dl><section><h3>What was found</h3><p>{selected.detail}</p></section><section className="recommendation"><h3>Recommended action</h3><p>{selected.recommendation}</p></section>{relatedFindings.length > 0 && <section><h3>Other findings on this resource</h3><div className="relatedList">{relatedFindings.map((finding, index) => <button key={`${finding.id}-${index}`} onClick={() => setSelected(finding)}><span className={`severityDot ${finding.severity}`} /><div><strong>{finding.title}</strong><small>{finding.status} · {finding.id}</small></div></button>)}</div></section>}{selected.references.length > 0 && <section><h3>References</h3>{selected.references.slice(0, 5).map((reference) => <a key={reference} href={reference} target="_blank" rel="noreferrer">{reference}</a>)}</section>}</aside></div>}
    </main>
  );
}

export default function Home() {
  if (!cloudConfigured) return <Dashboard cloudEnabled={false} />;
  return (
    <Authenticator loginMechanisms={["email"]} signUpAttributes={["email"]}>
      {({ signOut, user }) => (
        <Dashboard
          cloudEnabled
          userEmail={user?.signInDetails?.loginId ?? user?.username}
          onSignOut={signOut}
        />
      )}
    </Authenticator>
  );
}
