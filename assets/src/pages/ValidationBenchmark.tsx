import { useState, useCallback, useMemo } from 'react';
import { PageProps } from '@/types';
import { Head, router } from '@inertiajs/react';
import { logger } from '@/lib/logger';
import { safeCapitalize } from '@/lib/utils';

interface CategoryRates {
  [key: string]: number;
}

interface Competitor {
  id: string;
  name: string;
  overall: number;
  categories: CategoryRates;
  source?: string;
}

interface Category {
  id: string;
  name: string;
  mitreTacticId: string;
}

interface Strength {
  category: string;
  rate: number;
  above_average_by: number;
}

interface Weakness {
  category: string;
  rate: number;
  below_average_by: number;
}

interface Recommendation {
  priority: string;
  category: string;
  recommendation: string;
  techniques: string[];
}

interface Props extends PageProps {
  tamandua: Competitor;
  competitors: Competitor[];
  strengths: Strength[];
  weaknesses: Weakness[];
  recommendations: Recommendation[];
  categories: Category[];
}

export default function ValidationBenchmark({
  tamandua: initialTamandua,
  competitors: initialCompetitors,
  strengths: initialStrengths,
  weaknesses: initialWeaknesses,
  recommendations: initialRecommendations,
  categories
}: Props) {
  const [tamandua, setTamandua] = useState<Competitor>(initialTamandua);
  const [competitors, setCompetitors] = useState<Competitor[]>(initialCompetitors);
  const [strengths, setStrengths] = useState<Strength[]>(initialStrengths);
  const [weaknesses, setWeaknesses] = useState<Weakness[]>(initialWeaknesses);
  const [recommendations, setRecommendations] = useState<Recommendation[]>(initialRecommendations);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [selectedView, setSelectedView] = useState<'overview' | 'details'>('overview');

  const hasIndustryBaselines = competitors.length > 0;
  const allCompetitors = useMemo(() => [tamandua, ...competitors], [tamandua, competitors]);
  const rankedCompetitors = useMemo(
    () => [...allCompetitors].sort((a, b) => b.overall - a.overall),
    [allCompetitors]
  );

  const getBarColor = (value: number, max: number) => {
    const percentage = (value / max) * 100;
    if (percentage >= 90) return 'bg-green-500';
    if (percentage >= 75) return 'bg-blue-500';
    if (percentage >= 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const formatCategoryName = (category: string) => {
    return category.split('_').map((word) => safeCapitalize(word)).join(' ');
  };

  // Refresh benchmark data from API
  const refreshBenchmark = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/validation/benchmark');
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }

      const data = await response.json();

      if (data.success && data.comparison) {
        // Update Tamandua rates
        const tamanduaRates = data.comparison.tamandua || {};
        const overallRate = Object.keys(tamanduaRates).length > 0
          ? Object.values(tamanduaRates).reduce((sum: number, v) => sum + (v as number), 0) / Object.keys(tamanduaRates).length * 100
          : 0;

        setTamandua({
          ...tamandua,
          overall: Math.round(overallRate * 10) / 10,
          categories: Object.fromEntries(
            Object.entries(tamanduaRates).map(([k, v]) => [k, Math.round((v as number) * 1000) / 10])
          )
        });

        // Update strengths, weaknesses, and recommendations
        if (data.comparison.strengths) {
          setStrengths(data.comparison.strengths);
        }
        if (data.comparison.weaknesses) {
          setWeaknesses(data.comparison.weaknesses);
        }
        if (data.comparison.recommendations) {
          setRecommendations(data.comparison.recommendations);
        }

        setLastRefresh(new Date());
      } else {
        setError(data.error || 'Failed to fetch benchmark data');
      }
    } catch (err) {
      logger.error('Failed to refresh benchmark:', err);
      setError(err instanceof Error ? err.message : 'Failed to refresh benchmark');
    } finally {
      setIsLoading(false);
    }
  }, [tamandua]);

  // Refresh via Inertia (full page props reload)
  const handleRefresh = () => {
    router.reload({ only: ['tamandua', 'competitors', 'strengths', 'weaknesses', 'recommendations'] });
  };

  // Calculate ranking position
  const getRanking = () => {
    return rankedCompetitors.findIndex(c => c.id === 'tamandua') + 1;
  };

  // Calculate category averages
  const getCategoryAverage = (categoryId: string) => {
    const rates = competitors.map(c => c.categories[categoryId] || 0).filter(r => r > 0);
    return rates.length > 0 ? rates.reduce((sum, r) => sum + r, 0) / rates.length : 0;
  };

  // Get performance indicator
  const getPerformanceIndicator = (rate: number, average: number) => {
    const diff = rate - average;
    if (diff > 5) return { color: 'text-green-400', icon: '+', label: 'Above Average' };
    if (diff < -5) return { color: 'text-red-400', icon: '-', label: 'Below Average' };
    return { color: 'text-[var(--muted)]', icon: '=', label: 'Average' };
  };

  const ranking = getRanking();

  return (
    <>
      <Head title="Detection Benchmark" />

      <div className="min-h-screen" style={{ background: 'var(--bg)', color: 'var(--fg)' }}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8 flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>Detection Benchmark</h1>
              <p className="mt-2" style={{ color: 'var(--muted)' }}>
                Tamandua-owned validation from executed tests, persisted evidence, and source health.
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-sm" style={{ color: 'var(--subtle)' }}>
                Last updated: {lastRefresh.toLocaleTimeString()}
              </span>
              <button
                onClick={refreshBenchmark}
                disabled={isLoading}
                className="px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-2"
                style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Refreshing...
                  </>
                ) : (
                  'Refresh Data'
                )}
              </button>
              <a
                href="/app/validation"
                className="px-4 py-2 rounded font-medium transition-colors"
                style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
              >
                Back to Tests
              </a>
            </div>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="mb-6 bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
              <span className="text-red-400">{error}</span>
              <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
                Dismiss
              </button>
            </div>
          )}

          {/* Quick Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="card-sentinel rounded-lg p-4">
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Tamandua Overall</div>
              <div className="text-2xl font-bold text-blue-400">{tamandua.overall.toFixed(1)}%</div>
            </div>
            <div className="card-sentinel rounded-lg p-4">
              <div className="text-sm" style={{ color: 'var(--muted)' }}>
                {hasIndustryBaselines ? 'Industry Ranking' : 'Benchmark Mode'}
              </div>
              <div className="text-2xl font-bold text-purple-400">
                {hasIndustryBaselines ? `#${ranking} of ${allCompetitors.length}` : 'Internal'}
              </div>
            </div>
            <div className="card-sentinel rounded-lg p-4">
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Strengths</div>
              <div className="text-2xl font-bold text-green-400">{strengths.length}</div>
            </div>
            <div className="card-sentinel rounded-lg p-4">
              <div className="text-sm" style={{ color: 'var(--muted)' }}>Areas to Improve</div>
              <div className="text-2xl font-bold text-orange-400">{weaknesses.length}</div>
            </div>
          </div>

          {/* View Toggle */}
          <div className="mb-6 flex gap-2">
            <button
              onClick={() => setSelectedView('overview')}
              className={`px-4 py-2 rounded font-medium transition-colors ${
                selectedView === 'overview'
                  ? 'bg-blue-600 text-white'
                  : ''
              }`}
              style={selectedView !== 'overview' ? { background: 'var(--surface-2)', color: 'var(--fg-2)' } : undefined}
            >
              Overview
            </button>
            <button
              onClick={() => setSelectedView('details')}
              className={`px-4 py-2 rounded font-medium transition-colors ${
                selectedView === 'details'
                  ? 'bg-blue-600 text-white'
                  : ''
              }`}
              style={selectedView !== 'details' ? { background: 'var(--surface-2)', color: 'var(--fg-2)' } : undefined}
            >
              Detailed Comparison
            </button>
          </div>

          {selectedView === 'overview' ? (
            <>
              {/* Overall Comparison */}
              <div className="card-sentinel rounded-lg p-6 mb-8">
                <h2 className="text-xl font-semibold mb-6" style={{ color: 'var(--fg)' }}>Overall Detection Rate</h2>
                {!hasIndustryBaselines && (
                  <div className="mb-5 rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-sm" style={{ color: 'var(--fg-2)' }}>
                    No sourced competitor baseline is configured. This view shows Tamandua validation only; external comparisons stay hidden until they are backed by imported evaluation data.
                  </div>
                )}
                <div className="space-y-4">
                  {rankedCompetitors.map((competitor, index) => (
                    <div key={competitor.id} className="flex items-center gap-4">
                      <div className="w-8 text-center text-sm font-mono" style={{ color: 'var(--subtle)' }}>
                        #{index + 1}
                      </div>
                      <div className="w-48 text-sm">
                        <span className={competitor.id === 'tamandua' ? 'font-bold text-blue-400' : ''} style={competitor.id !== 'tamandua' ? { color: 'var(--fg-2)' } : undefined}>
                          {competitor.name}
                        </span>
                        {competitor.source && (
                          <div className="text-xs truncate" style={{ color: 'var(--subtle)' }}>{competitor.source}</div>
                        )}
                      </div>
                      <div className="flex-1 h-8 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
                        <div
                          className={`h-full ${competitor.id === 'tamandua' ? 'bg-blue-500' : getBarColor(competitor.overall, 100)} transition-all duration-500`}
                          style={{ width: `${competitor.overall}%` }}
                        />
                      </div>
                      <div className="w-16 text-right font-mono font-bold" style={{ color: 'var(--fg)' }}>
                        {competitor.overall.toFixed(1)}%
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Strengths & Weaknesses */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                {/* Strengths */}
                <div className="card-sentinel rounded-lg p-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                    <span className="text-green-400">+</span> Strengths
                  </h2>
                  {(strengths || []).length > 0 ? (
                    <div className="space-y-3">
                      {strengths.map((strength, idx) => (
                        <div key={idx} className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                          <div className="font-medium text-green-400">
                            {formatCategoryName(strength.category)}
                          </div>
                          <div className="text-sm mt-1" style={{ color: 'var(--fg-2)' }}>
                            {(strength.rate * 100).toFixed(1)}% detection rate
                            <span className="text-green-400 ml-2">
                              (+{(strength.above_average_by * 100).toFixed(1)}% above average)
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ color: 'var(--muted)' }}>Run more tests to identify strengths</p>
                  )}
                </div>

                {/* Weaknesses */}
                <div className="card-sentinel rounded-lg p-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                    <span className="text-red-400">!</span> Areas for Improvement
                  </h2>
                  {(weaknesses || []).length > 0 ? (
                    <div className="space-y-3">
                      {weaknesses.map((weakness, idx) => (
                        <div key={idx} className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                          <div className="font-medium text-red-400">
                            {formatCategoryName(weakness.category)}
                          </div>
                          <div className="text-sm mt-1" style={{ color: 'var(--fg-2)' }}>
                            {(weakness.rate * 100).toFixed(1)}% detection rate
                            <span className="text-red-400 ml-2">
                              (-{(weakness.below_average_by * 100).toFixed(1)}% below average)
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ color: 'var(--muted)' }}>Run more tests to identify weaknesses</p>
                  )}
                </div>
              </div>
            </>
          ) : (
            /* Detailed Category Breakdown */
            <div className="card-sentinel rounded-lg p-6 mb-8">
              <h2 className="text-xl font-semibold mb-6" style={{ color: 'var(--fg)' }}>Detection by MITRE ATT&CK Tactic</h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Tactic</th>
                      {allCompetitors.map(c => (
                        <th key={c.id} className={`text-right py-3 px-4 font-medium ${c.id === 'tamandua' ? 'text-blue-400' : ''}`} style={c.id !== 'tamandua' ? { color: 'var(--muted)' } : undefined}>
                          {c.name.split(' ')[0]}
                        </th>
                      ))}
                      <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Avg</th>
                      <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {categories.map(category => {
                      const tamanduaRate = tamandua.categories[category.id] || 0;
                      const avg = getCategoryAverage(category.id);
                      const indicator = getPerformanceIndicator(tamanduaRate, avg);

                      return (
                        <tr key={category.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                          <td className="py-3 px-4">
                            <div className="font-medium" style={{ color: 'var(--fg)' }}>{category.name}</div>
                            <div className="text-xs" style={{ color: 'var(--subtle)' }}>{category.mitreTacticId}</div>
                          </td>
                          {allCompetitors.map(competitor => {
                            const rate = competitor.categories[category.id] || 0;
                            return (
                              <td key={competitor.id} className="text-right py-3 px-4">
                                <span className={`font-mono ${
                                  rate >= 90 ? 'text-green-400' :
                                  rate >= 75 ? 'text-blue-400' :
                                  rate >= 60 ? 'text-yellow-400' :
                                  rate > 0 ? 'text-red-400' :
                                  ''
                                }`} style={rate === 0 ? { color: 'var(--dim)' } : undefined}>
                                  {rate > 0 ? `${rate.toFixed(1)}%` : '-'}
                                </span>
                              </td>
                            );
                          })}
                          <td className="text-right py-3 px-4 font-mono" style={{ color: 'var(--subtle)' }}>
                            {avg > 0 ? `${avg.toFixed(1)}%` : '-'}
                          </td>
                          <td className="text-right py-3 px-4">
                            <span className={`${indicator.color} font-medium`}>
                              {indicator.icon} {tamanduaRate > 0 ? indicator.label : 'No data'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div className="card-sentinel rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4" style={{ color: 'var(--fg)' }}>Recommendations</h2>
            {(recommendations || []).length > 0 ? (
              <div className="space-y-4">
                {recommendations.map((rec, idx) => (
                  <div key={idx} className={`border-l-4 rounded-r-lg p-4 ${
                    rec.priority === 'critical' ? 'border-red-500 bg-red-500/10' :
                    rec.priority === 'high' ? 'border-orange-500 bg-orange-500/10' :
                    rec.priority === 'medium' ? 'border-yellow-500 bg-yellow-500/10' :
                    'border-green-500 bg-green-500/10'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${
                        rec.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                        rec.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        rec.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {rec.priority}
                      </span>
                      <span className="text-sm" style={{ color: 'var(--muted)' }}>
                        {formatCategoryName(rec.category)}
                      </span>
                    </div>
                    <p style={{ color: 'var(--fg)' }}>{rec.recommendation}</p>
                    {rec.techniques && rec.techniques.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {rec.techniques.map(tech => (
                          <span key={tech} className="px-2 py-0.5 rounded text-xs" style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}>
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <p className="mb-4" style={{ color: 'var(--muted)' }}>
                  No recommendations yet. Run tests to generate actionable insights.
                </p>
                <a
                  href="/app/validation"
                  className="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded font-medium transition-colors"
                  style={{ color: 'white' }}
                >
                  Start Testing
                </a>
              </div>
            )}
          </div>

          {/* Legend */}
          <div className="mt-8 card-sentinel rounded-lg p-4">
            <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Detection Rate Legend</h4>
            <div className="flex flex-wrap gap-6">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Excellent (90%+)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Good (75-89%)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Needs Work (60-74%)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Critical (&lt;60%)</span>
              </div>
            </div>
          </div>

          {/* Data Source Note */}
          <div className="mt-4 text-sm text-center" style={{ color: 'var(--subtle)' }}>
            {hasIndustryBaselines ? (
              <>
                External baseline data is shown only when a sourced baseline is configured.
                <br />
                <a
                  href="https://attackevals.mitre-engenuity.org/results/enterprise"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300"
                >
                  View MITRE ATT&CK Evaluations
                </a>
              </>
            ) : (
              'Coverage is based on Tamandua validation runs. No competitor claims are displayed without sourced baseline data.'
            )}
          </div>
        </div>
      </div>
    </>
  );
}
