"""Training and evaluation routines."""
from src.training.evaluate import evaluate_model, save_metrics
from src.training.train import generate_synthetic_dataset

__all__ = ["evaluate_model", "save_metrics", "generate_synthetic_dataset"]
