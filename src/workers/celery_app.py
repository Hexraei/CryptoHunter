"""
CryptoHunter Celery Application
Background task processing for firmware analysis
"""

import os
from celery import Celery

# Get broker and backend URLs from environment
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

# Create Celery app
celery_app = Celery(
    'cryptohunter',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=['src.workers.tasks']
)

# Configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    result_expires=86400,  # Results expire after 24 hours
)

# Task routing
celery_app.conf.task_routes = {
    'src.workers.tasks.analyze_firmware_task': {'queue': 'analysis'},
    'src.workers.tasks.ghidra_task': {'queue': 'ghidra'},
    'src.workers.tasks.gnn_inference_task': {'queue': 'inference'},
}
