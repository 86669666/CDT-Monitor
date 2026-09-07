import { useMemo, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

type ChartPoint = { at: number; traffic: number }
type DisplayPoint = { at: number; traffic: number | null }
type ZonedParts = { year: number; month: number; day: number; hour: number; minute: number; second: number }

const HOUR = 60 * 60 * 1000
const DEFAULT_TIME_ZONE = 'Asia/Shanghai'

export function resolveTimeZone(timeZone?: string) {
  const zone = timeZone?.trim() || DEFAULT_TIME_ZONE
  try {
    Intl.DateTimeFormat('en-US', { timeZone: zone }).format(new Date())
    return zone
  } catch {
    return DEFAULT_TIME_ZONE
  }
}

function zonedParts(timestamp: number, timeZone: string): ZonedParts {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(timestamp))
  const values: Record<string, string> = {}
  for (const part of parts) {
    if (part.type !== 'literal') values[part.type] = part.value
  }
  return {
    year: Number(values.year),
    month: Number(values.month),
    day: Number(values.day),
    hour: Number(values.hour),
    minute: Number(values.minute),
    second: Number(values.second),
  }
}

function zonedInstant(parts: Pick<ZonedParts, 'year' | 'month' | 'day' | 'hour' | 'minute' | 'second'>, timeZone: string) {
  const utcGuess = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second)
  const lookedUp = zonedParts(utcGuess, timeZone)
  const asUTC = Date.UTC(lookedUp.year, lookedUp.month - 1, lookedUp.day, lookedUp.hour, lookedUp.minute, lookedUp.second)
  return utcGuess - (asUTC - utcGuess)
}

function startOfZonedDay(timestamp: number, timeZone: string) {
  const parts = zonedParts(timestamp, timeZone)
  return zonedInstant({ year: parts.year, month: parts.month, day: parts.day, hour: 0, minute: 0, second: 0 }, timeZone)
}

function shiftZonedDay(timestamp: number, days: number, timeZone: string) {
  const parts = zonedParts(timestamp, timeZone)
  const shifted = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days, 12, 0, 0))
  return startOfZonedDay(shifted.getTime(), timeZone)
}

function startOfUtcHour(timestamp: number) {
  return Math.floor(timestamp / HOUR) * HOUR
}

function buildTimeline(data: ChartPoint[], range: 'hourly' | 'daily', timeZone: string) {
  const slotCount = range === 'hourly' ? 25 : 31
  const latestPoint = data.reduce((latest, point) => Math.max(latest, point.at), 0)
  const currentSlot = range === 'hourly' ? startOfUtcHour(Date.now()) : startOfZonedDay(Date.now(), timeZone)
  const latestSlot = range === 'hourly' ? startOfUtcHour(latestPoint) : startOfZonedDay(latestPoint, timeZone)
  const end = Math.max(currentSlot, latestSlot)
  const values = new Map(data.map((point) => [
    range === 'hourly' ? startOfUtcHour(point.at) : startOfZonedDay(point.at, timeZone),
    point.traffic,
  ]))

  return Array.from({ length: slotCount }, (_, index): DisplayPoint => {
    const offset = slotCount - 1 - index
    const at = range === 'hourly' ? end - offset * HOUR : shiftZonedDay(end, -offset, timeZone)
    return { at, traffic: values.get(at) ?? null }
  })
}

function hourLabel(timestamp: number, timeZone: string) {
  return new Date(timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone })
}

function dayLabel(timestamp: number, timeZone: string) {
  return new Date(timestamp).toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric', timeZone })
}

export default function HistoryChart({ data, range, timeZone }: { data: ChartPoint[]; range: 'hourly' | 'daily'; timeZone: string }) {
  const zone = resolveTimeZone(timeZone)
  const [chartWidth, setChartWidth] = useState(900)
  const timeline = useMemo(() => buildTimeline(data, range, zone), [data, range, zone])
  const sampleCount = timeline.filter((point) => point.traffic !== null).length
  const isCompact = chartWidth < 520
  const tickStep = range === 'hourly' ? (isCompact ? 6 : 4) : (isCompact ? 10 : 5)
  const ticks = timeline.filter((_, index) => index % tickStep === 0 || index === timeline.length - 1).map((point) => point.at)
  const formatLabel = (value: number) => (range === 'hourly' ? hourLabel(value, zone) : dayLabel(value, zone))
  const tooltip = {
    contentStyle: {
      background: 'rgba(255, 255, 255, .96)',
      border: '1px solid rgba(173, 178, 184, .45)',
      borderRadius: 10,
      boxShadow: '0 16px 32px -20px rgba(15, 23, 42, .36)',
      fontSize: 12,
    },
    formatter: (value: number | string) => [typeof value === 'number' ? value.toFixed(3) : value, '流量 (GB)'] as [string | number, string],
    labelFormatter: (value: number) => formatLabel(value),
  }
  const axis = { tickLine: false, axisLine: false, tick: { fill: '#737780', fontSize: isCompact ? 10 : 11 } }
  const margin = isCompact
    ? { top: 10, right: 10, bottom: 2, left: 2 }
    : { top: 10, right: 18, bottom: 2, left: -8 }

  return (
    <ResponsiveContainer width="100%" height="100%" debounce={80} onResize={(width) => setChartWidth(width)}>
      {range === 'hourly' ? (
        <LineChart data={timeline} margin={margin}>
          <CartesianGrid stroke="rgba(173, 178, 184, .32)" vertical={false} />
          <XAxis
            dataKey="at"
            type="number"
            scale="time"
            domain={[timeline[0].at, timeline[timeline.length - 1].at]}
            allowDataOverflow
            ticks={ticks}
            tickFormatter={(value: number) => hourLabel(value, zone)}
            interval={0}
            minTickGap={isCompact ? 12 : 18}
            padding={{ left: isCompact ? 3 : 8, right: isCompact ? 3 : 8 }}
            {...axis}
          />
          <YAxis width={isCompact ? 40 : 48} tickFormatter={(value: number) => Number(value.toFixed(3)).toString()} {...axis} />
          <Tooltip {...tooltip} />
          <Line
            type="monotone"
            dataKey="traffic"
            connectNulls={false}
            isAnimationActive={false}
            stroke="#111315"
            strokeWidth={2.25}
            dot={sampleCount <= 4 ? { r: 3, fill: '#111315', stroke: '#fff', strokeWidth: 2 } : false}
            activeDot={{ r: 4, fill: '#111315', stroke: '#fff', strokeWidth: 2 }}
          />
        </LineChart>
      ) : (
        <BarChart data={timeline} margin={margin}>
          <CartesianGrid stroke="rgba(173, 178, 184, .32)" vertical={false} />
          <XAxis
            dataKey="at"
            type="number"
            scale="time"
            domain={[timeline[0].at, timeline[timeline.length - 1].at]}
            allowDataOverflow
            ticks={ticks}
            tickFormatter={(value: number) => dayLabel(value, zone)}
            interval={0}
            minTickGap={isCompact ? 10 : 16}
            padding={{ left: isCompact ? 3 : 8, right: isCompact ? 3 : 8 }}
            {...axis}
          />
          <YAxis width={isCompact ? 40 : 48} tickFormatter={(value: number) => Number(value.toFixed(3)).toString()} {...axis} />
          <Tooltip {...tooltip} />
          <Bar dataKey="traffic" fill="#111315" barSize={isCompact ? 12 : 20} maxBarSize={isCompact ? 16 : 26} isAnimationActive={false} radius={[4, 4, 0, 0]} />
        </BarChart>
      )}
    </ResponsiveContainer>
  )
}
