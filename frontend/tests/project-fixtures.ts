import type { BenchmarkArtifact, ValidationArtifact } from '../src/types';

export const validationArtifact: ValidationArtifact = {
  status: 'validated',
  is_current: true,
  started_at: '2026-01-15T11:00:00Z',
  completed_at: '2026-01-15T11:00:03.125Z',
  duration_seconds: 3.125,
  total_tests_passed: 17,
  backend: {
    passed: 11,
    failed: 0,
    total: 11,
    coverage_percent: 92.5,
    categories: {
      parser: { passed: 4, failed: 0, total: 4 },
      security: { passed: 3, failed: 0, total: 3 },
    },
  },
  frontend: { passed: 6, failed: 0, total: 6 },
  detections: { passed: 5, failed: 0, total: 5, benign_passed: 2, benign_total: 2 },
  steps: [
    {
      name: 'Backend tests',
      command: ['python', '-m', 'pytest', 'backend/tests'],
      status: 'passed',
      exit_code: 0,
      duration_seconds: 1.05,
    },
    {
      name: 'Frontend tests',
      command: 'npm --prefix frontend test',
      status: 'passed',
      exit_code: 0,
      duration_seconds: 2.075,
    },
  ],
  source_fingerprint: '1'.repeat(64),
};

export const benchmarkArtifact: BenchmarkArtifact = {
  status: 'passed',
  is_current: true,
  events_processed: 120,
  events_per_second: 241.75,
  detection_seconds: 0.0000123,
  alerts_generated: 3,
  rules_evaluated: 840,
  active_rules: 7,
  measured_at: '2026-01-15T11:00:04.012345Z',
  scope: 'Isolated controlled benchmark fixture',
};
