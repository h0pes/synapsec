import { useParams } from '@tanstack/react-router'

export function ApplicationDetailPage() {
  const { id } = useParams({ strict: false })

  return (
    <div>
      <h1 className="text-2xl font-bold">Application Detail</h1>
      <p className="mt-2 text-muted-foreground">Application ID: {id}</p>
    </div>
  )
}
