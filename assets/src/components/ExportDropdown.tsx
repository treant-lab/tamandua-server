import { useState, useRef, useEffect } from 'react'
import { Download, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { exportToCSV, exportToJSON } from '@/utils/export'

interface ExportDropdownProps {
  getData: () => Record<string, any>[]
  filenameBase: string
  label?: string
  className?: string
  disabled?: boolean
}

export function ExportDropdown({
  getData,
  filenameBase,
  label = 'Export',
  className,
  disabled = false,
}: ExportDropdownProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const timestamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

  const handleExportCSV = () => {
    const data = getData()
    if (data.length === 0) return
    exportToCSV(data, `${filenameBase}-${timestamp()}`)
    setOpen(false)
  }

  const handleExportJSON = () => {
    const data = getData()
    if (data.length === 0) return
    exportToJSON(data, `${filenameBase}-${timestamp()}`)
    setOpen(false)
  }

  return (
    <div ref={ref} className={cn('relative', className)}>
      <button
        onClick={() => setOpen(!open)}
        disabled={disabled}
        className={cn(
          'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
          disabled
            ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
            : 'bg-slate-700 hover:bg-slate-600 text-slate-300'
        )}
      >
        <Download className="h-4 w-4" />
        {label}
        <ChevronDown className={cn('h-3 w-3 transition-transform', open && 'rotate-180')} />
      </button>

      {open && !disabled && (
        <div className="absolute right-0 top-full mt-1 z-50 w-40 bg-slate-700 border border-slate-600 rounded-lg shadow-xl overflow-hidden">
          <button
            onClick={handleExportCSV}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-600 transition-colors text-left"
          >
            <span className="text-xs font-mono px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded">CSV</span>
            Export as CSV
          </button>
          <button
            onClick={handleExportJSON}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-600 transition-colors text-left"
          >
            <span className="text-xs font-mono px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded">JSON</span>
            Export as JSON
          </button>
        </div>
      )}
    </div>
  )
}
