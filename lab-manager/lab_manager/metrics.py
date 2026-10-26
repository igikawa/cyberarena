from prometheus_client import Counter, Gauge, Histogram


LAB_LAUNCHES = Counter(
    "cyberarena_lab_launches_total",
    "User laboratory launch attempts by outcome",
    ("challenge", "result"),
)
LAB_LAUNCH_DURATION = Histogram(
    "cyberarena_lab_launch_duration_seconds",
    "Time spent provisioning a user laboratory",
    ("challenge",),
)
ACTIVE_LABS = Gauge(
    "cyberarena_active_labs",
    "Number of active user laboratory containers",
)
LAB_EXPIRATIONS = Counter(
    "cyberarena_lab_expirations_total",
    "User laboratories removed after TTL expiration",
)
LAB_REJECTIONS = Counter(
    "cyberarena_lab_rejections_total",
    "Laboratory requests rejected by bounded policy",
    ("reason",),
)
LAB_MATERIAL_UPDATES = Counter(
    "cyberarena_lab_material_updates_total",
    "Challenge material changes that invalidated active laboratories",
    ("challenge",),
)
DOCKER_UP = Gauge(
    "cyberarena_lab_docker_up",
    "Whether the isolated Docker daemon and runsc runtime are available",
)
