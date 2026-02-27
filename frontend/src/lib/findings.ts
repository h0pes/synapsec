import type { SeverityLevel } from '@/types/finding'

/** Map source_tool identifiers to their full display names. */
export const TOOL_DISPLAY_NAMES: Record<string, string> = {
  sonarqube: 'SonarQube',
  jfrog_xray: 'JFrog Xray',
  tenable_was: 'Tenable WAS',
}

/** Map source_tool identifiers to category abbreviations. */
export const TOOL_CATEGORY_LABELS: Record<string, string> = {
  sonarqube: 'SAST',
  jfrog_xray: 'SCA',
  tenable_was: 'DAST',
}

/** Tailwind badge styles per finding category. */
export const CATEGORY_BADGE_STYLES: Record<string, string> = {
  SAST: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  SCA: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  DAST: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
}

/** Tailwind badge styles keyed by source_tool identifier. */
export const TOOL_BADGE_STYLES: Record<string, string> = {
  sonarqube: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  jfrog_xray: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  tenable_was: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
}

/** Normalize a severity string to the canonical SeverityLevel type. */
export function normalizeSeverity(raw: string): SeverityLevel {
  const lower = raw.toLowerCase()
  const map: Record<string, SeverityLevel> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  }
  return map[lower] ?? 'Info'
}
