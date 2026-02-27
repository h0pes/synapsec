import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { TablePagination } from '@/components/ui/table-pagination'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import * as correlationApi from '@/api/correlation'
import type {
  CorrelationRule,
  CorrelationGroup,
  CorrelationGroupDetail,
  ConfidenceLevel,
} from '@/types/correlation'

/** Mapping from confidence level to Tailwind color classes. */
const CONFIDENCE_STYLES: Record<ConfidenceLevel, string> = {
  High: 'bg-green-600 text-white hover:bg-green-700',
  Medium: 'bg-yellow-500 text-black hover:bg-yellow-600',
  Low: 'bg-red-500 text-white hover:bg-red-600',
}

/** Map tool names to display-friendly labels for coverage badges. */
const TOOL_LABELS: Record<string, string> = {
  sonarqube: 'SonarQube',
  'jfrog xray': 'JFrog Xray',
  jfrog_xray: 'JFrog Xray',
  'tenable was': 'Tenable WAS',
  tenable_was: 'Tenable WAS',
}

function toolLabel(tool: string): string {
  return TOOL_LABELS[tool.toLowerCase()] ?? tool
}

/** Format rule_type for display (e.g. "cross_tool" -> "Cross-Tool"). */
function formatRuleType(ruleType: string): string {
  return ruleType
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join('-')
}

export function CorrelationPage() {
  const { t } = useTranslation()

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t('correlation.title')}</h1>

      <Tabs defaultValue="rules">
        <TabsList>
          <TabsTrigger value="rules">{t('correlation.tabs.rules')}</TabsTrigger>
          <TabsTrigger value="groups">{t('correlation.tabs.groups')}</TabsTrigger>
        </TabsList>

        <TabsContent value="rules">
          <RulesTab />
        </TabsContent>

        <TabsContent value="groups">
          <GroupsTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

/* ── Rules Tab ─────────────────────────────────────────────────────── */

function RulesTab() {
  const { t } = useTranslation()
  const [rules, setRules] = useState<CorrelationRule[]>([])
  const [loading, setLoading] = useState(false)

  const fetchRules = useCallback(async () => {
    setLoading(true)
    try {
      const data = await correlationApi.listRules()
      setRules(data)
    } catch {
      // handled by API client
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchRules()
  }, [fetchRules])

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.loading')}
      </div>
    )
  }

  if (rules.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  return (
    <div className="mt-4 rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('correlation.rules.name')}</TableHead>
            <TableHead>{t('correlation.rules.type')}</TableHead>
            <TableHead>{t('correlation.rules.confidence')}</TableHead>
            <TableHead>{t('correlation.rules.active')}</TableHead>
            <TableHead className="text-right">{t('correlation.rules.priority')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell className="font-medium">{rule.name}</TableCell>
              <TableCell>
                <Badge variant="outline">{formatRuleType(rule.rule_type)}</Badge>
              </TableCell>
              <TableCell>
                <Badge className={CONFIDENCE_STYLES[rule.confidence]}>
                  {rule.confidence}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge
                  variant={rule.is_active ? 'default' : 'secondary'}
                  className={
                    rule.is_active
                      ? 'bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900 dark:text-green-200'
                      : 'bg-gray-100 text-gray-500 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-400'
                  }
                >
                  {rule.is_active ? t('correlation.rules.yes') : t('correlation.rules.no')}
                </Badge>
              </TableCell>
              <TableCell className="text-right font-mono text-sm">
                {rule.priority}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

/* ── Groups Tab ────────────────────────────────────────────────────── */

function GroupsTab() {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<CorrelationGroup[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(false)
  const [expandedGroupId, setExpandedGroupId] = useState<string | null>(null)
  const [groupDetail, setGroupDetail] = useState<CorrelationGroupDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const perPage = 25

  const fetchGroups = useCallback(async () => {
    setLoading(true)
    try {
      const result = await correlationApi.listGroups(undefined, page, perPage)
      setGroups(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // handled by API client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchGroups()
  }, [fetchGroups])

  const handleExpandGroup = useCallback(
    async (groupId: string) => {
      if (expandedGroupId === groupId) {
        setExpandedGroupId(null)
        setGroupDetail(null)
        return
      }

      setExpandedGroupId(groupId)
      setDetailLoading(true)
      try {
        const detail = await correlationApi.getGroup(groupId)
        setGroupDetail(detail)
      } catch {
        // handled by API client
        setExpandedGroupId(null)
      } finally {
        setDetailLoading(false)
      }
    },
    [expandedGroupId],
  )

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.loading')}
      </div>
    )
  }

  if (groups.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  return (
    <div className="mt-4 space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? t('correlation.groups.groupSingular') : t('correlation.groups.groupPlural')}
        </span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[40px]" />
              <TableHead>{t('correlation.groups.group')}</TableHead>
              <TableHead className="text-right">{t('correlation.groups.members')}</TableHead>
              <TableHead>{t('correlation.groups.toolCoverage')}</TableHead>
              <TableHead>{t('correlation.groups.created')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((group) => (
              <GroupRow
                key={group.id}
                group={group}
                isExpanded={expandedGroupId === group.id}
                detail={expandedGroupId === group.id ? groupDetail : null}
                detailLoading={expandedGroupId === group.id && detailLoading}
                onToggle={handleExpandGroup}
              />
            ))}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <TablePagination page={page} totalPages={totalPages} onPageChange={setPage} />
      )}
    </div>
  )
}

/* ── Group Row with Expand ─────────────────────────────────────────── */

function GroupRow({
  group,
  isExpanded,
  detail,
  detailLoading,
  onToggle,
}: {
  group: CorrelationGroup
  isExpanded: boolean
  detail: CorrelationGroupDetail | null
  detailLoading: boolean
  onToggle: (id: string) => void
}) {
  const { t } = useTranslation()

  /** Number of columns in the groups table (expand icon + 4 data columns). */
  const groupColumnCount = 5

  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/50"
        onClick={() => onToggle(group.id)}
      >
        <TableCell className="w-[40px]">
          {isExpanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </TableCell>
        <TableCell className="font-medium">
          {group.primary_finding_id.slice(0, 8)}...
        </TableCell>
        <TableCell className="text-right font-mono text-sm">
          {group.member_count}
        </TableCell>
        <TableCell>
          <div className="flex gap-1">
            {group.tool_coverage.map((tool) => (
              <Badge key={tool} variant="outline" className="text-xs">
                {toolLabel(tool)}
              </Badge>
            ))}
          </div>
        </TableCell>
        <TableCell className="text-sm text-muted-foreground">
          {new Date(group.created_at).toLocaleDateString()}
        </TableCell>
      </TableRow>

      {isExpanded && (
        <TableRow>
          <TableCell colSpan={groupColumnCount} className="bg-muted/30 p-4">
            {detailLoading ? (
              <div className="flex items-center justify-center py-4 text-muted-foreground">
                {t('common.loading')}
              </div>
            ) : detail ? (
              <div className="space-y-2">
                <h4 className="text-sm font-semibold">
                  {t('correlation.groups.memberFindings')}
                </h4>
                <div className="rounded-md border bg-background">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('correlation.groups.findingTitle')}</TableHead>
                        <TableHead>{t('correlation.groups.severity')}</TableHead>
                        <TableHead>{t('correlation.groups.category')}</TableHead>
                        <TableHead>{t('correlation.groups.sourceTool')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detail.members.map((member) => (
                        <TableRow key={member.id}>
                          <TableCell className="max-w-[300px] truncate font-medium">
                            {member.title}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={member.normalized_severity} />
                          </TableCell>
                          <TableCell>{member.finding_category}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {member.source_tool}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ) : null}
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
