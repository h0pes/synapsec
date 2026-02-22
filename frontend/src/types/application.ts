export type AssetCriticality =
  | 'Very_High'
  | 'High'
  | 'Medium_High'
  | 'Medium'
  | 'Medium_Low'
  | 'Low'

export type AppStatus = 'Active' | 'Deprecated' | 'Decommissioned'

export type ApplicationSummary = {
  id: string
  app_name: string
  app_code: string
  criticality: AssetCriticality | null
  status: AppStatus
  business_unit: string | null
  is_verified: boolean
  created_at: string
}

export type Application = {
  id: string
  app_name: string
  app_code: string
  description: string | null
  criticality: AssetCriticality | null
  tier: string
  business_unit: string | null
  business_owner: string | null
  technical_owner: string | null
  security_champion: string | null
  technology_stack: string[]
  deployment_environment: string[]
  exposure: string | null
  data_classification: string | null
  regulatory_scope: string[]
  status: AppStatus
  is_verified: boolean
  ssa_code: string | null
  ssa_name: string | null
  effective_office_owner: string | null
  effective_office_name: string | null
  is_dora_fei: boolean
  is_gdpr_subject: boolean
  has_pci_data: boolean
  is_psd2_relevant: boolean
  created_at: string
  updated_at: string
}

export type CreateApplication = {
  app_name: string
  app_code: string
  description?: string
  criticality?: AssetCriticality
  business_unit?: string
  business_owner?: string
  technical_owner?: string
}

export type PagedResult<T> = {
  items: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}
