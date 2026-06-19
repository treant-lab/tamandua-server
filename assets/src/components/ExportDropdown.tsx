import { Download, ChevronDown } from 'lucide-react'
import { Menu, MenuItem } from '@/components/ui/baseui'
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
  const timestamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

  const handleExportCSV = () => {
    const data = getData()
    if (data.length === 0) return
    exportToCSV(data, `${filenameBase}-${timestamp()}`)
  }

  const handleExportJSON = () => {
    const data = getData()
    if (data.length === 0) return
    exportToJSON(data, `${filenameBase}-${timestamp()}`)
  }

  return (
    <div className={className}>
      <Menu
        align="end"
        className="w-44"
        trigger={
          <button
            type="button"
            disabled={disabled}
            className={cn(
              'flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
              disabled
                ? 'cursor-not-allowed bg-slate-800 text-slate-500'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            )}
          >
            <Download className="h-4 w-4" />
            {label}
            <ChevronDown className="h-3 w-3" />
          </button>
        }
      >
        <MenuItem onSelect={handleExportCSV} disabled={disabled}>
          <>
            <span className="text-xs font-mono px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded">CSV</span>
            Export as CSV
          </>
        </MenuItem>
        <MenuItem onSelect={handleExportJSON} disabled={disabled}>
          <>
            <span className="text-xs font-mono px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded">JSON</span>
            Export as JSON
          </>
        </MenuItem>
      </Menu>
    </div>
  )
}
