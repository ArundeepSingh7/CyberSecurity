# Abstraction
class ThreatEngineError(Exception):
    """Base exception for threat engine."""


# Abstraction
class NotFittedError(ThreatEngineError):
    """Raised when an estimator or pipeline is used before fitting."""


# Abstraction
class DataLoadError(ThreatEngineError):
    """Raised when dataset loading or validation fails."""


# Abstraction
class ModelNotFoundError(ThreatEngineError):
    """Raised when saved model artifacts cannot be found."""
