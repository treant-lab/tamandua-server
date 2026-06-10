import { useState, useRef, useEffect } from 'react';
import {
  ChevronDown, ExternalLink, Search, Copy,
  Cpu, Globe, File, Server, Settings,
  Activity, Share2, Eye
} from 'lucide-react';
import { GraphNodeType } from '@/types';
import { logger } from '@/lib/logger';

interface PivotOption {
  id: string;
  label: string;
  icon: typeof Cpu;
  action: () => void;
  description?: string;
}

interface EntityPivotProps {
  entityType: GraphNodeType;
  entityId: string;
  entityLabel: string;
  entityData: Record<string, unknown>;
  position?: 'bottom-left' | 'bottom-right' | 'top-left' | 'top-right';
  onPivot?: (pivotType: string, entityData: Record<string, unknown>) => void;
}

const ENTITY_ICONS: Record<GraphNodeType, typeof Cpu> = {
  process: Cpu,
  network: Globe,
  file: File,
  dns: Server,
  registry: Settings,
};

export default function EntityPivot({
  entityType,
  entityId,
  entityLabel,
  entityData,
  position = 'bottom-left',
  onPivot,
}: EntityPivotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      logger.error('Failed to copy:', err);
    }
  };

  const handlePivot = (pivotType: string) => {
    onPivot?.(pivotType, entityData);
    setIsOpen(false);
  };

  const getPivotOptions = (): PivotOption[] => {
    const baseOptions: PivotOption[] = [
      {
        id: 'view-graph',
        label: 'View in Graph',
        icon: Share2,
        action: () => handlePivot('graph'),
        description: 'Open investigation graph centered on this entity',
      },
    ];

    switch (entityType) {
      case 'process':
        return [
          ...baseOptions,
          {
            id: 'view-tree',
            label: 'View Process Tree',
            icon: Activity,
            action: () => handlePivot('process-tree'),
            description: 'Show in process tree view',
          },
          {
            id: 'view-network',
            label: 'View Network Activity',
            icon: Globe,
            action: () => handlePivot('network'),
            description: 'Filter network by this process',
          },
          {
            id: 'view-files',
            label: 'View File Activity',
            icon: File,
            action: () => handlePivot('files'),
            description: 'Filter files by this process',
          },
          {
            id: 'hunt-hash',
            label: 'Hunt for Hash',
            icon: Search,
            action: () => handlePivot('hunt-hash'),
            description: 'Search for this SHA256 hash',
          },
          {
            id: 'hunt-cmdline',
            label: 'Hunt for Command',
            icon: Search,
            action: () => handlePivot('hunt-cmdline'),
            description: 'Search for similar command lines',
          },
        ];

      case 'network':
        return [
          ...baseOptions,
          {
            id: 'view-process',
            label: 'View Process',
            icon: Cpu,
            action: () => handlePivot('process'),
            description: 'Show process that made this connection',
          },
          {
            id: 'hunt-ip',
            label: 'Hunt for IP',
            icon: Search,
            action: () => handlePivot('hunt-ip'),
            description: 'Search for this IP address',
          },
          {
            id: 'hunt-domain',
            label: 'Hunt for Domain',
            icon: Search,
            action: () => handlePivot('hunt-domain'),
            description: 'Search for associated domain',
          },
          {
            id: 'threat-intel',
            label: 'Check Threat Intel',
            icon: Eye,
            action: () => handlePivot('threat-intel'),
            description: 'Look up in threat intel feeds',
          },
        ];

      case 'file':
        return [
          ...baseOptions,
          {
            id: 'view-process',
            label: 'View Process',
            icon: Cpu,
            action: () => handlePivot('process'),
            description: 'Show process that accessed this file',
          },
          {
            id: 'hunt-hash',
            label: 'Hunt for Hash',
            icon: Search,
            action: () => handlePivot('hunt-hash'),
            description: 'Search for this file hash',
          },
          {
            id: 'hunt-path',
            label: 'Hunt for Path',
            icon: Search,
            action: () => handlePivot('hunt-path'),
            description: 'Search for similar file paths',
          },
        ];

      case 'dns':
        return [
          ...baseOptions,
          {
            id: 'view-process',
            label: 'View Process',
            icon: Cpu,
            action: () => handlePivot('process'),
            description: 'Show process that made this query',
          },
          {
            id: 'hunt-domain',
            label: 'Hunt for Domain',
            icon: Search,
            action: () => handlePivot('hunt-domain'),
            description: 'Search for this domain',
          },
          {
            id: 'threat-intel',
            label: 'Check Threat Intel',
            icon: Eye,
            action: () => handlePivot('threat-intel'),
            description: 'Look up in threat intel feeds',
          },
        ];

      case 'registry':
        return [
          ...baseOptions,
          {
            id: 'view-process',
            label: 'View Process',
            icon: Cpu,
            action: () => handlePivot('process'),
            description: 'Show process that modified this key',
          },
          {
            id: 'hunt-key',
            label: 'Hunt for Key',
            icon: Search,
            action: () => handlePivot('hunt-key'),
            description: 'Search for this registry key',
          },
        ];

      default:
        return baseOptions;
    }
  };

  const getCopyableFields = (): { label: string; value: string }[] => {
    const fields: { label: string; value: string }[] = [];

    switch (entityType) {
      case 'process':
        if (entityData.sha256) fields.push({ label: 'SHA256', value: String(entityData.sha256) });
        if (entityData.cmdline) fields.push({ label: 'Command', value: String(entityData.cmdline) });
        if (entityData.path) fields.push({ label: 'Path', value: String(entityData.path) });
        if (entityData.pid) fields.push({ label: 'PID', value: String(entityData.pid) });
        break;

      case 'network':
        if (entityData.remote_ip) fields.push({ label: 'IP', value: String(entityData.remote_ip) });
        if (entityData.remote_port) fields.push({ label: 'Port', value: String(entityData.remote_port) });
        break;

      case 'file':
        if (entityData.path) fields.push({ label: 'Path', value: String(entityData.path) });
        if (entityData.sha256) fields.push({ label: 'SHA256', value: String(entityData.sha256) });
        break;

      case 'dns':
        if (entityData.domain) fields.push({ label: 'Domain', value: String(entityData.domain) });
        break;

      case 'registry':
        if (entityData.key) fields.push({ label: 'Key', value: String(entityData.key) });
        break;
    }

    return fields;
  };

  const Icon = ENTITY_ICONS[entityType];
  const pivotOptions = getPivotOptions();
  const copyableFields = getCopyableFields();

  const positionClasses = {
    'bottom-left': 'top-full left-0 mt-1',
    'bottom-right': 'top-full right-0 mt-1',
    'top-left': 'bottom-full left-0 mb-1',
    'top-right': 'bottom-full right-0 mb-1',
  };

  return (
    <div className="relative inline-block" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors text-sm"
      >
        <Icon size={14} className="text-gray-400" />
        <span className="text-gray-200 max-w-[150px] truncate">{entityLabel}</span>
        <ChevronDown
          size={14}
          className={`text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`}
        />
      </button>

      {isOpen && (
        <div
          className={`absolute z-50 w-72 bg-gray-800 rounded-lg shadow-xl border border-gray-700 ${positionClasses[position]}`}
        >
          {/* Header */}
          <div className="p-3 border-b border-gray-700">
            <div className="flex items-center gap-2">
              <Icon size={16} className="text-gray-400" />
              <div>
                <div className="text-sm font-medium text-gray-200 truncate">
                  {entityLabel}
                </div>
                <div className="text-xs text-gray-500 capitalize">{entityType}</div>
              </div>
            </div>
          </div>

          {/* Copyable Fields */}
          {copyableFields.length > 0 && (
            <div className="p-2 border-b border-gray-700">
              <div className="text-xs text-gray-500 mb-1 px-1">Copy Values</div>
              <div className="space-y-1">
                {copyableFields.map(field => (
                  <button
                    key={field.label}
                    onClick={() => copyToClipboard(field.value, field.label)}
                    className="w-full flex items-center justify-between gap-2 px-2 py-1 hover:bg-gray-700 rounded text-sm transition-colors"
                  >
                    <span className="text-gray-400 text-xs">{field.label}:</span>
                    <span className="text-gray-200 truncate max-w-[150px] text-xs font-mono">
                      {field.value}
                    </span>
                    <Copy
                      size={12}
                      className={copiedField === field.label ? 'text-green-400' : 'text-gray-500'}
                    />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Pivot Options */}
          <div className="p-2">
            <div className="text-xs text-gray-500 mb-1 px-1">Pivot To</div>
            <div className="space-y-0.5">
              {pivotOptions.map(option => {
                const OptionIcon = option.icon;
                return (
                  <button
                    key={option.id}
                    onClick={option.action}
                    className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-gray-700 rounded text-left transition-colors group"
                  >
                    <OptionIcon size={14} className="text-gray-500 group-hover:text-gray-300" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-gray-200">{option.label}</div>
                      {option.description && (
                        <div className="text-xs text-gray-500 truncate">{option.description}</div>
                      )}
                    </div>
                    <ExternalLink size={12} className="text-gray-600 group-hover:text-gray-400" />
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
