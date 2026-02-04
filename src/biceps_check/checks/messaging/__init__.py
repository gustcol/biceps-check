"""
Security checks for Azure Messaging resources.

This module contains security rules for:
- Service Bus (Microsoft.ServiceBus/namespaces)
- Event Hub (Microsoft.EventHub/namespaces)
- Event Grid (Microsoft.EventGrid/topics, domains)
"""

from biceps_check.checks.messaging.event_hub import *
from biceps_check.checks.messaging.service_bus import *
