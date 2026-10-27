from prometheus_client import Counter, Histogram


HTTP_REQUESTS = Counter(
    "cyberarena_http_requests_total",
    "HTTP requests handled by the platform",
    ("method", "route", "status"),
)
HTTP_REQUEST_DURATION = Histogram(
    "cyberarena_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ("method", "route"),
)
FLAG_SUBMISSIONS = Counter(
    "cyberarena_flag_submissions_total",
    "Flag submission outcomes",
    ("result",),
)
SOLVES_AWARDED = Counter(
    "cyberarena_solves_awarded_total",
    "First-time challenge solves awarded",
)
REGISTRATIONS = Counter(
    "cyberarena_registrations_total",
    "Successful user registrations",
)
