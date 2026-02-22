import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { FindingStatus } from '@/types/finding'

type Props = {
  open: boolean
  onClose: () => void
  targetStatus: FindingStatus
  onConfirm: (data: {
    justification?: string
    committed_date?: string
    expiry_date?: string
  }) => void
}

const REQUIRES_JUSTIFICATION: FindingStatus[] = [
  'Risk_Accepted',
  'False_Positive',
]
const REQUIRES_COMMITTED_DATE: FindingStatus[] = ['Deferred_Remediation']
const REQUIRES_EXPIRY_DATE: FindingStatus[] = ['Risk_Accepted']

export function FindingTransitionDialog({
  open,
  onClose,
  targetStatus,
  onConfirm,
}: Props) {
  const [justification, setJustification] = useState('')
  const [committedDate, setCommittedDate] = useState('')
  const [expiryDate, setExpiryDate] = useState('')

  const needsJustification = REQUIRES_JUSTIFICATION.includes(targetStatus)
  const needsCommittedDate = REQUIRES_COMMITTED_DATE.includes(targetStatus)
  const needsExpiryDate = REQUIRES_EXPIRY_DATE.includes(targetStatus)

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onConfirm({
      justification: justification || undefined,
      committed_date: committedDate || undefined,
      expiry_date: expiryDate || undefined,
    })
    setJustification('')
    setCommittedDate('')
    setExpiryDate('')
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            Transition to {targetStatus.replace(/_/g, ' ')}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {needsJustification && (
            <div className="space-y-2">
              <Label htmlFor="justification">Justification (required)</Label>
              <Input
                id="justification"
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                required
              />
            </div>
          )}
          {needsCommittedDate && (
            <div className="space-y-2">
              <Label htmlFor="committed_date">Committed Date (required)</Label>
              <Input
                id="committed_date"
                type="date"
                value={committedDate}
                onChange={(e) => setCommittedDate(e.target.value)}
                required
              />
            </div>
          )}
          {needsExpiryDate && (
            <div className="space-y-2">
              <Label htmlFor="expiry_date">Expiry Date (required)</Label>
              <Input
                id="expiry_date"
                type="date"
                value={expiryDate}
                onChange={(e) => setExpiryDate(e.target.value)}
                required
              />
            </div>
          )}
          {!needsJustification && !needsCommittedDate && !needsExpiryDate && (
            <div className="space-y-2">
              <Label htmlFor="justification">Justification (optional)</Label>
              <Input
                id="justification"
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
              />
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Confirm</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
