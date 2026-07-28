class WorkflowInvariantError(ValueError):
    """Raised when a workflow transition would make persisted state unsafe."""