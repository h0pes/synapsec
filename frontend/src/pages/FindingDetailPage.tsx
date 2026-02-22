import { useParams } from '@tanstack/react-router'

export function FindingDetailPage() {
  const { id } = useParams({ strict: false })

  return (
    <div>
      <h1 className="text-2xl font-bold">Finding Detail</h1>
      <p className="mt-2 text-muted-foreground">Finding ID: {id}</p>
    </div>
  )
}
