/**
 * Export Utilities
 *
 * Provides functionality for exporting dashboard widgets as images,
 * generating PDF reports, downloading data as CSV/JSON, and scheduling automated exports.
 */

import { logger } from '@/lib/logger'

// ============================================================================
// Types
// ============================================================================

export interface ExportOptions {
  format: 'png' | 'jpeg' | 'svg' | 'pdf'
  quality?: number // 0-1 for jpeg
  scale?: number // DPI multiplier
  filename?: string
  backgroundColor?: string
  width?: number
  height?: number
}

export interface PDFReportOptions {
  title: string
  subtitle?: string
  author?: string
  includeTimestamp?: boolean
  includeLogo?: boolean
  orientation?: 'portrait' | 'landscape'
  pageSize?: 'a4' | 'letter' | 'legal'
  margins?: {
    top: number
    right: number
    bottom: number
    left: number
  }
  sections?: PDFSection[]
}

export interface PDFSection {
  type: 'heading' | 'text' | 'chart' | 'table' | 'divider' | 'metric'
  content: unknown
  pageBreakBefore?: boolean
  pageBreakAfter?: boolean
}

export interface ScheduledExport {
  id: string
  name: string
  schedule: 'daily' | 'weekly' | 'monthly'
  recipients: string[]
  format: 'pdf' | 'csv' | 'xlsx'
  dashboardId: string
  enabled: boolean
  lastRun?: number
  nextRun: number
}

// ============================================================================
// CSV Export Functions
// ============================================================================

/**
 * Converts an array of objects to CSV format and triggers a browser download.
 * Handles nested objects by JSON-stringifying them.
 */
export function exportToCSV(data: Record<string, unknown>[], filename: string): void {
  if (!data || data.length === 0) return

  // Collect all unique keys across all objects
  const keys = Array.from(
    data.reduce((acc, row) => {
      Object.keys(row).forEach(k => acc.add(k))
      return acc
    }, new Set<string>())
  )

  // Build CSV header
  const header = keys.map(k => escapeCSVField(k)).join(',')

  // Build CSV rows
  const rows = data.map(row =>
    keys.map(key => {
      const value = row[key]
      if (value === null || value === undefined) return ''
      if (typeof value === 'object') return escapeCSVField(JSON.stringify(value))
      return escapeCSVField(String(value))
    }).join(',')
  )

  const csv = [header, ...rows].join('\n')
  downloadBlobInternal(csv, ensureExtension(filename, '.csv'), 'text/csv;charset=utf-8;')
}

/**
 * Converts data to CSV format with custom column mapping
 */
export function convertToCSV(
  data: Record<string, unknown>[],
  columns?: { key: string; header: string }[]
): string {
  if (data.length === 0) return ''

  const headers = columns
    ? columns.map(c => c.header)
    : Object.keys(data[0])

  const keys = columns
    ? columns.map(c => c.key)
    : Object.keys(data[0])

  const rows = data.map(row =>
    keys.map(key => {
      const value = row[key]
      if (value === null || value === undefined) return ''
      if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))) {
        return `"${value.replace(/"/g, '""')}"`
      }
      return String(value)
    }).join(',')
  )

  return [headers.join(','), ...rows].join('\n')
}

/**
 * Downloads data as CSV file with custom columns
 */
export function downloadCSV(
  data: Record<string, unknown>[],
  filename: string,
  columns?: { key: string; header: string }[]
): void {
  const csv = convertToCSV(data, columns)
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  downloadBlob(blob, filename.endsWith('.csv') ? filename : `${filename}.csv`)
}

// ============================================================================
// JSON Export Functions
// ============================================================================

/**
 * Exports an array of objects as a formatted JSON file and triggers a browser download.
 */
export function exportToJSON(data: Record<string, unknown>[] | Record<string, unknown>, filename: string): void {
  if (!data) return
  const json = JSON.stringify(data, null, 2)
  downloadBlobInternal(json, ensureExtension(filename, '.json'), 'application/json;charset=utf-8;')
}

// ============================================================================
// Screenshot/Image Export Functions
// ============================================================================

/**
 * Captures a DOM element as an image using the Canvas API
 */
export async function captureElementAsImage(
  element: HTMLElement,
  options: ExportOptions = { format: 'png' }
): Promise<Blob> {
  const { format, quality = 0.92, scale = 2, backgroundColor = '#0f172a' } = options

  // Get element dimensions
  const rect = element.getBoundingClientRect()
  const width = options.width || rect.width
  const height = options.height || rect.height

  // Create canvas
  const canvas = document.createElement('canvas')
  canvas.width = width * scale
  canvas.height = height * scale
  const ctx = canvas.getContext('2d')

  if (!ctx) {
    throw new Error('Failed to get canvas context')
  }

  // Set background
  ctx.fillStyle = backgroundColor
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.scale(scale, scale)

  // For SVG elements, serialize and draw
  if (element instanceof SVGElement || element.querySelector('svg')) {
    const svgElement = element instanceof SVGElement ? element : element.querySelector('svg')
    if (svgElement) {
      const svgData = new XMLSerializer().serializeToString(svgElement)
      const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' })
      const url = URL.createObjectURL(svgBlob)

      const img = new Image()
      img.crossOrigin = 'anonymous'

      await new Promise<void>((resolve, reject) => {
        img.onload = () => {
          ctx.drawImage(img, 0, 0, width, height)
          URL.revokeObjectURL(url)
          resolve()
        }
        img.onerror = reject
        img.src = url
      })
    }
  }

  // Convert to blob
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (blob) {
          resolve(blob)
        } else {
          reject(new Error('Failed to create blob'))
        }
      },
      format === 'jpeg' ? 'image/jpeg' : 'image/png',
      quality
    )
  })
}

/**
 * Downloads an element as an image file
 */
export async function downloadElementAsImage(
  element: HTMLElement,
  options: ExportOptions = { format: 'png' }
): Promise<void> {
  const blob = await captureElementAsImage(element, options)
  const filename = options.filename || `export-${Date.now()}.${options.format}`
  downloadBlob(blob, filename)
}

/**
 * Copies an element screenshot to clipboard
 */
export async function copyElementToClipboard(element: HTMLElement): Promise<void> {
  const blob = await captureElementAsImage(element, { format: 'png' })

  try {
    await navigator.clipboard.write([
      new ClipboardItem({ 'image/png': blob })
    ])
  } catch (error) {
    logger.error('Failed to copy to clipboard:', error)
    throw new Error('Clipboard access denied')
  }
}

// ============================================================================
// PDF Generation Functions
// ============================================================================

/**
 * Generates a PDF report from dashboard data
 * Note: In production, this would use a library like jsPDF or pdfmake
 */
export async function generatePDFReport(
  options: PDFReportOptions,
  data: Record<string, unknown>
): Promise<Blob> {
  const pdfContent = buildPDFContent(options, data)

  // For now, return a JSON representation
  // In production, use jsPDF, pdfmake, or server-side PDF generation
  const blob = new Blob([JSON.stringify(pdfContent, null, 2)], {
    type: 'application/json'
  })

  return blob
}

function buildPDFContent(
  options: PDFReportOptions,
  data: Record<string, unknown>
): object {
  return {
    metadata: {
      title: options.title,
      subtitle: options.subtitle,
      author: options.author || 'Tamandua EDR',
      generatedAt: new Date().toISOString(),
      orientation: options.orientation || 'portrait',
      pageSize: options.pageSize || 'a4',
    },
    sections: options.sections || [],
    data,
  }
}

/**
 * Downloads a PDF report
 */
export async function downloadPDFReport(
  options: PDFReportOptions,
  data: Record<string, unknown>
): Promise<void> {
  const blob = await generatePDFReport(options, data)
  const filename = `${options.title.toLowerCase().replace(/\s+/g, '-')}-${formatDateForFilename(new Date())}.pdf`
  downloadBlob(blob, filename)
}

// ============================================================================
// Scheduled Export Functions
// ============================================================================

/**
 * Creates a scheduled export configuration
 */
export async function createScheduledExport(
  config: Omit<ScheduledExport, 'id' | 'lastRun' | 'nextRun'>
): Promise<ScheduledExport> {
  const response = await fetch('/api/v1/reports/scheduled', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })

  if (!response.ok) {
    throw new Error('Failed to create scheduled export')
  }

  return response.json()
}

/**
 * Lists all scheduled exports
 */
export async function listScheduledExports(): Promise<ScheduledExport[]> {
  const response = await fetch('/api/v1/reports/scheduled')

  if (!response.ok) {
    throw new Error('Failed to fetch scheduled exports')
  }

  const result = await response.json()
  return result.data
}

/**
 * Updates a scheduled export
 */
export async function updateScheduledExport(
  id: string,
  updates: Partial<ScheduledExport>
): Promise<ScheduledExport> {
  const response = await fetch(`/api/v1/reports/scheduled/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  })

  if (!response.ok) {
    throw new Error('Failed to update scheduled export')
  }

  return response.json()
}

/**
 * Deletes a scheduled export
 */
export async function deleteScheduledExport(id: string): Promise<void> {
  const response = await fetch(`/api/v1/reports/scheduled/${id}`, {
    method: 'DELETE',
  })

  if (!response.ok) {
    throw new Error('Failed to delete scheduled export')
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function escapeCSVField(field: string): string {
  if (field.includes(',') || field.includes('"') || field.includes('\n') || field.includes('\r')) {
    return `"${field.replace(/"/g, '""')}"`
  }
  return field
}

function ensureExtension(filename: string, ext: string): string {
  if (filename.endsWith(ext)) return filename
  return filename + ext
}

// Internal download function for string content
function downloadBlobInternal(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Downloads a blob as a file
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Formats a date for use in filenames
 */
export function formatDateForFilename(date: Date): string {
  return date.toISOString().split('T')[0]
}

/**
 * Formats a timestamp for display
 */
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleString()
}

// ============================================================================
// React Hook for Export Button
// ============================================================================

export interface UseExportButtonOptions {
  elementRef: React.RefObject<HTMLElement>
  filename?: string
  onExportStart?: () => void
  onExportComplete?: () => void
  onExportError?: (error: Error) => void
}

export function useExportButton(options: UseExportButtonOptions) {
  const { elementRef, filename = 'export', onExportStart, onExportComplete, onExportError } = options

  const exportAsPNG = async () => {
    if (!elementRef.current) return

    try {
      onExportStart?.()
      await downloadElementAsImage(elementRef.current, {
        format: 'png',
        filename: `${filename}-${formatDateForFilename(new Date())}.png`,
      })
      onExportComplete?.()
    } catch (error) {
      onExportError?.(error instanceof Error ? error : new Error('Export failed'))
    }
  }

  const exportAsJPEG = async () => {
    if (!elementRef.current) return

    try {
      onExportStart?.()
      await downloadElementAsImage(elementRef.current, {
        format: 'jpeg',
        filename: `${filename}-${formatDateForFilename(new Date())}.jpg`,
        quality: 0.9,
      })
      onExportComplete?.()
    } catch (error) {
      onExportError?.(error instanceof Error ? error : new Error('Export failed'))
    }
  }

  const copyToClipboard = async () => {
    if (!elementRef.current) return

    try {
      onExportStart?.()
      await copyElementToClipboard(elementRef.current)
      onExportComplete?.()
    } catch (error) {
      onExportError?.(error instanceof Error ? error : new Error('Copy to clipboard failed'))
    }
  }

  return {
    exportAsPNG,
    exportAsJPEG,
    copyToClipboard,
  }
}
