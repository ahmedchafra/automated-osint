export type VectorType = 'INFRASTRUCTURE' | 'SERVICES' | 'IDENTITY' | 'SEARCH' | 'USERNAME';

export type EntityType =
  | 'SUBDOMAIN'
  | 'IP_ADDRESS'
  | 'PORT_SERVICE'
  | 'CVE'
  | 'EMAIL'
  | 'BREACH'
  | 'PROFILE'
  | 'DORK_RESULT'
  | 'TECHNOLOGY'
  | 'TECHNOLOGY_VERSION'
  | 'OPEN_PORT'
  | 'GITHUB_REPO'
  | 'LEAKED_SECRET'
  | 'TELEGRAM_CHANNEL'
  | 'TELEGRAM_MESSAGE'
  | 'TLS_CERT'
  | 'TLS_ASSESSMENT'
  | 'HOST_METADATA'
  | 'DNS_RECORD'
  | 'DNS_POSTURE'
  | 'DOMAIN_METADATA'
  | 'EMAIL_PLATFORM'
  | 'LOOKALIKE_DOMAIN'
  | 'ONION_SITE'
  | 'DARKWEB_MENTION'
  | 'CREDENTIAL'
  | 'URL'
  | 'PHISHING_SITE'
  | 'CLOUD_BUCKET'
  | 'EXPOSED_FILE'
  | 'ASN_INFO'
  | 'HTTP_HEADER'
  | 'HISTORICAL_URL'
  | 'WAYBACK_SNAPSHOT'
  | 'VULNERABILITY'
  | 'CRAWLED_PAGE'
  | 'WEB_ENDPOINT'
  | 'WEB_FORM'
  | 'WEB_PARAMETER'
  | 'JAVASCRIPT_ASSET'
  | 'TAKEOVER_ASSESSMENT'
  | 'CONTENT_DISCOVERY';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanStatus = 'QUEUED' | 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type ScanMode = 'passive' | 'validated' | 'active';
export type TargetType = 'domain' | 'ip' | 'organization';
export type JobStatus = 'QUEUED' | 'RUNNING' | 'RETRYING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type AssetState = 'CANDIDATE' | 'RESOLVED' | 'LIVE';
export type LinkType =
  | 'RESOLVES_TO'
  | 'HAS_PORT'
  | 'MATCHES_CVE'
  | 'HAS_VULNERABILITY'
  | 'BREACHED_IN'
  | 'REFERENCES'
  | 'EXPOSED_IN';

export interface ScopeManifest {
  allowed_domains?: string[];
  allowed_cidrs?: string[];
  excluded_domains?: string[];
  excluded_cidrs?: string[];
  excluded_url_paths?: string[];
  allowed_ports?: number[];
  allow_subdomains?: boolean;
  allow_resolved_ips?: boolean;
  included_assets?: string[];
  [key: string]: unknown;
}

export interface Scan {
  id: string;
  target_domain: string;
  target_type: TargetType;
  scan_mode: ScanMode;
  status: ScanStatus;
  celery_task_id?: string | null;
  selected_vectors: VectorType[];
  target_usernames: string[];
  scope_manifest: ScopeManifest;
  created_at: string;
  completed_at?: string | null;
  updated_at?: string | null;
  findings_count: number;
  links_count: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  vector_type: VectorType;
  entity_type: EntityType;
  entity_value: string;
  severity: Severity;
  confidence: number;
  source_module: string;
  raw_data: Record<string, unknown>;
  normalized_data: Record<string, unknown>;
  tags: string[];
  created_at: string;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  revision: number;
  last_observed_for?: string | null;
}

export interface PaginatedFindings {
  items: Finding[];
  total: number;
  skip: number;
  limit: number;
}

export interface ScanFacets {
  findings_total: number;
  findings_by_entity_type: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_by_source: Record<string, number>;
  findings_by_vector: Record<string, number>;
  assets_total: number;
  assets_in_scope: number;
  assets_wildcard_suspected: number;
  assets_by_state: Record<string, number>;
  jobs_total: number;
  jobs_by_status: Record<string, number>;
}

export interface ScanJob {
  id: string;
  scan_id: string;
  parent_job_id?: string | null;
  celery_task_id: string;
  job_type: string;
  stage: string;
  status: JobStatus;
  input_type?: string | null;
  input_value?: string | null;
  progress: {
    event?: string;
    payload?: Record<string, unknown>;
    updated_at?: string;
    [key: string]: unknown;
  };
  result_summary: Record<string, unknown>;
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  updated_at: string;
}

export interface Asset {
  id: string;
  scan_id: string;
  asset_type: string;
  value: string;
  canonical_value: string;
  registrable_domain?: string | null;
  state: AssetState;
  in_scope: boolean;
  scope_reason: string;
  wildcard_suspected: boolean;
  source_modules: string[];
  evidence_count: number;
  dns_records: Record<string, unknown>;
  resolved_ips: string[];
  http_metadata: Record<string, unknown>;
  created_at: string;
  last_observed_at: string;
  updated_at: string;
}

export interface AssetObservation {
  id: string;
  scan_id: string;
  asset_id: string;
  asset_type: string;
  canonical_value: string;
  state: AssetState;
  source_module?: string | null;
  event_type: string;
  in_scope: boolean;
  wildcard_suspected: boolean;
  evidence: Record<string, unknown>;
  observed_at: string;
  created_at: string;
}

export interface ScreenshotEvidence {
  id: string;
  scan_id: string;
  asset_id?: string | null;
  url: string;
  sha256: string;
  width: number;
  height: number;
  page_title?: string | null;
  status_code?: number | null;
  capture_metadata: Record<string, unknown>;
  created_at: string;
  image_url: string;
}

export interface EntityLink {
  id: string;
  scan_id: string;
  source_finding_id: string;
  target_finding_id: string;
  link_type: LinkType;
  confidence: number;
  created_at: string;
}
