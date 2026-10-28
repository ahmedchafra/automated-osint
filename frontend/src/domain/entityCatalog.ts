import type { EntityType } from '../types/api';

export type SpecialistTabId =
  | 'infrastructure'
  | 'identity'
  | 'web-osint'
  | 'secrets'
  | 'threat-intel'
  | 'brand';

interface EntityDefinition {
  label: string;
  tab: SpecialistTabId;
  description: string;
}

/**
 * Frontend display contract for every backend EntityType.
 * `satisfies Record<EntityType, ...>` intentionally makes the build fail when
 * an entity is missing or misspelled instead of silently hiding evidence.
 */
export const ENTITY_CATALOG = {
  SUBDOMAIN: { label: 'Subdomain', tab: 'infrastructure', description: 'Discovered DNS hostname' },
  IP_ADDRESS: { label: 'IP address', tab: 'infrastructure', description: 'Resolved or observed network address' },
  PORT_SERVICE: { label: 'Port service', tab: 'infrastructure', description: 'Network service associated with a port' },
  CVE: { label: 'CVE', tab: 'web-osint', description: 'Known vulnerability identifier' },
  EMAIL: { label: 'Email address', tab: 'identity', description: 'Publicly observed email identity' },
  BREACH: { label: 'Breach exposure', tab: 'identity', description: 'Breach evidence associated with an identity' },
  PROFILE: { label: 'Public profile', tab: 'identity', description: 'Account or public identity profile' },
  DORK_RESULT: { label: 'Search result', tab: 'brand', description: 'Result from a targeted search query' },
  TECHNOLOGY: { label: 'Technology', tab: 'web-osint', description: 'Detected software or web technology' },
  TECHNOLOGY_VERSION: { label: 'Technology version', tab: 'web-osint', description: 'Version evidence for detected software' },
  OPEN_PORT: { label: 'Open port', tab: 'infrastructure', description: 'Observed listening network port' },
  GITHUB_REPO: { label: 'GitHub repository', tab: 'secrets', description: 'Repository related to the target' },
  LEAKED_SECRET: { label: 'Leaked secret', tab: 'secrets', description: 'Potential credential or secret exposure' },
  TELEGRAM_CHANNEL: { label: 'Telegram channel', tab: 'threat-intel', description: 'Relevant public Telegram channel' },
  TELEGRAM_MESSAGE: { label: 'Telegram message', tab: 'threat-intel', description: 'Relevant Telegram message evidence' },
  TLS_CERT: { label: 'TLS certificate', tab: 'infrastructure', description: 'Certificate transparency or endpoint certificate' },
  TLS_ASSESSMENT: { label: 'TLS assessment', tab: 'web-osint', description: 'Protocol and cipher security assessment' },
  HOST_METADATA: { label: 'Host metadata', tab: 'infrastructure', description: 'HTTP and network host characteristics' },
  DNS_RECORD: { label: 'DNS record', tab: 'infrastructure', description: 'Observed DNS resource record' },
  DNS_POSTURE: { label: 'DNS posture', tab: 'infrastructure', description: 'DNS and email authentication posture' },
  DOMAIN_METADATA: { label: 'Domain metadata', tab: 'infrastructure', description: 'Registration or organization-domain evidence' },
  EMAIL_PLATFORM: { label: 'Email platform', tab: 'identity', description: 'Service usage associated with an email' },
  LOOKALIKE_DOMAIN: { label: 'Lookalike domain', tab: 'brand', description: 'Potential typosquat or impersonation domain' },
  ONION_SITE: { label: 'Onion site', tab: 'threat-intel', description: 'Tor hidden-service search result' },
  DARKWEB_MENTION: { label: 'Dark-web mention', tab: 'threat-intel', description: 'Target mention from a dark-web source' },
  CREDENTIAL: { label: 'Credential exposure', tab: 'secrets', description: 'Potentially exposed authentication material' },
  URL: { label: 'URL', tab: 'infrastructure', description: 'Discovered target URL' },
  PHISHING_SITE: { label: 'Phishing site', tab: 'brand', description: 'Potential brand impersonation or phishing property' },
  CLOUD_BUCKET: { label: 'Cloud bucket', tab: 'brand', description: 'Discovered cloud object-storage location' },
  EXPOSED_FILE: { label: 'Exposed file', tab: 'brand', description: 'Publicly accessible sensitive file' },
  ASN_INFO: { label: 'ASN information', tab: 'infrastructure', description: 'Network ownership and routing context' },
  HTTP_HEADER: { label: 'HTTP header', tab: 'web-osint', description: 'Observed response header or security-header result' },
  HISTORICAL_URL: { label: 'Historical URL', tab: 'web-osint', description: 'URL recovered from an archive or crawl index' },
  WAYBACK_SNAPSHOT: { label: 'Wayback snapshot', tab: 'web-osint', description: 'Archived web snapshot evidence' },
  VULNERABILITY: { label: 'Vulnerability', tab: 'web-osint', description: 'Validated or template-based security finding' },
  CRAWLED_PAGE: { label: 'Crawled page', tab: 'web-osint', description: 'Page found by the scoped crawler' },
  WEB_ENDPOINT: { label: 'Web endpoint', tab: 'web-osint', description: 'Discovered application endpoint' },
  WEB_FORM: { label: 'Web form', tab: 'web-osint', description: 'Observed HTML form' },
  WEB_PARAMETER: { label: 'Web parameter', tab: 'web-osint', description: 'Observed request parameter' },
  JAVASCRIPT_ASSET: { label: 'JavaScript asset', tab: 'web-osint', description: 'Referenced script or source-map candidate' },
  TAKEOVER_ASSESSMENT: { label: 'Takeover assessment', tab: 'infrastructure', description: 'Subdomain takeover verification result' },
  CONTENT_DISCOVERY: { label: 'Content discovery', tab: 'web-osint', description: 'Authorized content-discovery result' },
} satisfies Record<EntityType, EntityDefinition>;

export const ENTITY_TYPES = Object.keys(ENTITY_CATALOG) as EntityType[];

export const SPECIALIST_TAB_TYPES: Record<SpecialistTabId, EntityType[]> = {
  infrastructure: ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'infrastructure'),
  identity: ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'identity'),
  'web-osint': ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'web-osint'),
  secrets: ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'secrets'),
  'threat-intel': ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'threat-intel'),
  brand: ENTITY_TYPES.filter(type => ENTITY_CATALOG[type].tab === 'brand'),
};

export function entityLabel(type: string): string {
  return type in ENTITY_CATALOG
    ? ENTITY_CATALOG[type as EntityType].label
    : type.replaceAll('_', ' ').toLowerCase().replace(/^./, letter => letter.toUpperCase());
}
