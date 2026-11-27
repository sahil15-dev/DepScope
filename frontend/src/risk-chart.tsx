import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { Scan } from './api'
import { dateLabel, displayNumber, scanName } from './presentation'

export default function RiskChart({
  scans,
  connected,
}: {
  scans: Scan[]
  connected: boolean
}) {
  const points = scans.map((scan) => ({
    id: scan.id,
    label: dateLabel(scan.observed_at),
    name: scanName(scan),
    risk: scan.risk_index,
  }))
  const ticks = new Map<string, string>()
  for (const [index, point] of points.entries()) {
    ticks.set(
      point.id,
      point.label === points[index - 1]?.label ? '' : point.label,
    )
  }
  return (
    <>
      <div
        className="chart"
        role="img"
        aria-label={
          connected
            ? 'DepScope risk index over time, from zero to 100'
            : 'Independent saved risk scores, from zero to 100'
        }
      >
        <ResponsiveContainer
          width="100%"
          height="100%"
          initialDimension={{ width: 520, height: 220 }}
        >
          <AreaChart
            data={points}
            margin={{ top: 12, right: 12, bottom: 4, left: 2 }}
            accessibilityLayer={false}
          >
            <defs>
              <linearGradient id="risk-fill" x1="0" x2="0" y1="0" y2="1">
                <stop
                  offset="0%"
                  stopColor="var(--risk-plot)"
                  stopOpacity={0.25}
                />
                <stop
                  offset="100%"
                  stopColor="var(--risk-plot)"
                  stopOpacity={0.015}
                />
              </linearGradient>
            </defs>
            <CartesianGrid
              vertical={false}
              stroke="var(--border)"
              strokeDasharray="3 5"
            />
            <XAxis
              dataKey="id"
              tickFormatter={(id: string) => ticks.get(id) ?? ''}
              interval="preserveStartEnd"
              minTickGap={36}
              tickLine={false}
              axisLine={false}
              tick={{ fill: 'var(--subtle)', fontSize: 11 }}
            />
            <YAxis
              domain={[0, 100]}
              ticks={[0, 25, 50, 75, 100]}
              width={34}
              tickLine={false}
              axisLine={false}
              tick={{ fill: 'var(--subtle)', fontSize: 11 }}
            />
            <Tooltip
              labelFormatter={(id) => {
                const point = points.find((item) => item.id === id)
                return point ? `${point.name} · ${point.label}` : ''
              }}
              contentStyle={{
                background: 'var(--surface-high)',
                border: '1px solid var(--border)',
                borderRadius: 8,
              }}
              itemStyle={{ color: 'var(--text)' }}
              labelStyle={{ color: 'var(--muted)' }}
            />
            <Area
              type="linear"
              dataKey="risk"
              name="Risk index"
              stroke={connected ? 'var(--risk-plot)' : 'none'}
              fill={connected ? 'url(#risk-fill)' : 'none'}
              strokeWidth={2}
              dot={{
                r: 4,
                fill: 'var(--risk-plot)',
                stroke: 'var(--surface)',
                strokeWidth: 1,
              }}
              connectNulls={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <details className="trend-details">
        <summary>View trend values</summary>
        <ul>
          {points.map((point) => (
            <li key={point.id}>
              {point.name} · {point.label} — {displayNumber(point.risk)}
            </li>
          ))}
        </ul>
      </details>
    </>
  )
}
