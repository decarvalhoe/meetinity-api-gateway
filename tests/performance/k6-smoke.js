import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '3m', target: 600 },
    { duration: '10m', target: 600 },
    { duration: '30s', target: 1200 },
    { duration: '2m', target: 600 },
    { duration: '3m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<350', 'p(99)<650'],
    http_req_failed: ['rate<0.005'],
  },
};

const headers = {
  'Content-Type': 'application/json',
};

export default function () {
  const res = http.get(`${__ENV.GATEWAY_HOST}/api/users`, { headers });
  check(res, {
    'status is 200': (r) => r.status === 200,
    'content present': (r) => !!r.body,
  });
  sleep(Math.random());
}
