// Adapted k6 bench for asm
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { Counter } from 'k6/metrics';
import exec from 'k6/execution';

const testData = new SharedArray('test-data', function () {
    return JSON.parse(open('./test-data.json')).entries;
});
const expectedStats = JSON.parse(open('./test-data.json')).stats;

const tpCount = new Counter('tp_count');
const tnCount = new Counter('tn_count');
const fpCount = new Counter('fp_count');
const fnCount = new Counter('fn_count');
const errorCount = new Counter('error_count');
const emptyBodyCount = new Counter('empty_body_count');
const non200Count = new Counter('non_200_count');

export const options = {
    summaryTrendStats: ['p(99)'],
    systemTags: ['status', 'method'],
    dns: { ttl: '5m', select: 'roundRobin' },
    scenarios: {
        default: {
            executor: 'ramping-arrival-rate',
            startRate: 1,
            timeUnit: '1s',
            preAllocatedVUs: 100,
            maxVUs: 250,
            gracefulStop: '10s',
            stages: [{ duration: '120s', target: 900 }],
        },
    },
    thresholds: { http_req_failed: ['rate<0.01'] },
};

export default function () {
    const idx = exec.scenario.iterationInTest;
    if (idx >= testData.length) return;
    const entry = testData[idx];
    const expectedApproved = entry.expected_approved;

    const res = http.post(
        'http://localhost:19998/fraud-score',
        JSON.stringify(entry.request),
        { headers: { 'Content-Type': 'application/json' }, timeout: '2001ms' }
    );

    if (res.status !== 200) { non200Count.add(1); errorCount.add(1); return; }
    if (!res.body || res.body.length === 0) { emptyBodyCount.add(1); errorCount.add(1); return; }

    let body;
    try { body = JSON.parse(res.body); } catch { errorCount.add(1); return; }

    if (expectedApproved === body.approved) {
        if (body.approved) tnCount.add(1); else tpCount.add(1);
    } else {
        if (body.approved) fnCount.add(1); else fpCount.add(1);
    }
}

export function handleSummary(data) {
    const K = 1000, T_MAX_MS = 1000, P99_MIN_MS = 1, P99_MAX_MS = 2000;
    const EPSILON_MIN = 0.001, BETA = 300, TX_CORTE = 0.15;
    const SCORE_P99_CORTE = -3000, SCORE_DET_CORTE = -3000;
    const r = (v, d) => +v.toFixed(d);
    const httpDuration = data.metrics.http_req_duration.values;
    const p99 = httpDuration['p(99)'];
    const tp = data.metrics.tp_count ? data.metrics.tp_count.values.count : 0;
    const tn = data.metrics.tn_count ? data.metrics.tn_count.values.count : 0;
    const fp = data.metrics.fp_count ? data.metrics.fp_count.values.count : 0;
    const fn = data.metrics.fn_count ? data.metrics.fn_count.values.count : 0;
    const errs = data.metrics.error_count ? data.metrics.error_count.values.count : 0;
    const empty = data.metrics.empty_body_count ? data.metrics.empty_body_count.values.count : 0;
    const non200 = data.metrics.non_200_count ? data.metrics.non_200_count.values.count : 0;
    const N = tp + tn + fp + fn + errs;
    const E = (fp * 1) + (fn * 3) + (errs * 5);
    const failures = fp + fn + errs;
    const epsilon = N > 0 ? E / N : 0;
    const failureRate = N > 0 ? failures / N : 0;
    let p99Score, p99Cut = false;
    if (p99 <= 0) p99Score = 0;
    else if (p99 > P99_MAX_MS) { p99Score = SCORE_P99_CORTE; p99Cut = true; }
    else p99Score = (Math.log(p99 / P99_MAX_MS) / Math.log(P99_MIN_MS / P99_MAX_MS)) * 3000;
    let detScore, detCut = false;
    if (failureRate > TX_CORTE) { detScore = SCORE_DET_CORTE; detCut = true; }
    else { const absP = (epsilon - EPSILON_MIN) * BETA; detScore = 3000 + absP; }
    const finalScore = Math.max(0, p99Score) + Math.max(0, detScore);
    const result = {
        expected: expectedStats, p99,
        scoring: {
            breakdown: { true_positive: tp, true_negative: tn, false_positive: fp, false_negative: fn, http_errors: errs, empty_body: empty, non_200: non200 },
            failure_rate: r(failureRate, 6), weighted_errors_E: E, error_rate_epsilon: r(epsilon, 6),
            p99_score: { value: r(p99Score, 6), cut_triggered: p99Cut },
            detection_score: { value: r(detScore, 6), rate_component: 3000, absolute_penalty: r(detScore - 3000, 6), cut_triggered: detCut },
            final_score: r(finalScore, 6),
        },
    };
    return { 'results.json': JSON.stringify(result, null, 2), 'stdout': JSON.stringify(result, null, 2) };
}
